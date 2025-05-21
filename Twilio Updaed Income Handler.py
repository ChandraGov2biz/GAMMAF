"""
Updated Twilio Input Handler Lambda with Intent Recognition Integration
- Fixed chat loop functionality for SMS and voice conversations
- Enhanced DynamoDB persistence with cleanup for expired conversations
- Improved error handling, logging, and Twilio validation
- Removed in-memory storage reliance
- Added metrics for monitoring
- Fixed DynamoDB index, CallSid mapping, and request validation errors
- Standardized voice call conversation ID handling using CallSid

Date: May 2025
"""

import json
import os
import uuid
import time
from datetime import datetime, timedelta
import urllib.parse
import boto3
import base64
from botocore.exceptions import ClientError
from twilio.request_validator import RequestValidator
from twilio.twiml.voice_response import VoiceResponse
from twilio.twiml.messaging_response import MessagingResponse

# Configuration
TWILIO_AUTH_TOKEN = os.environ['TWILIO_AUTH_TOKEN','7eecd1171f814d9fdfad9daf4bd778c6']
CONVERSATION_TIMEOUT_MINUTES = int(os.environ.get('CONVERSATION_TIMEOUT_MINUTES', '30'))
INTENT_HANDLER_LAMBDA = os.environ['INTENT_HANDLER_LAMBDA', 'GAMMAFIntentHandler']
DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE','LiaAgentConversations']
SPEECH_LANGUAGE = os.environ.get('SPEECH_LANGUAGE', 'en-US')

# Initialize clients
lambda_client = boto3.client('lambda')
dynamodb = boto3.resource('dynamodb')
cloudwatch = boto3.client('cloudwatch')

def validate_environment():
    """Validate required environment variables."""
    required_vars = ['TWILIO_AUTH_TOKEN', 'INTENT_HANDLER_LAMBDA', 'DYNAMODB_TABLE']
    for var in required_vars:
        if not os.environ.get(var):
            raise EnvironmentError(f"Missing required environment variable: {var}")

validate_environment()

def validate_twilio_request(event):
    """Validates that requests are coming from Twilio."""
    try:
        validator = RequestValidator(TWILIO_AUTH_TOKEN)
        domain = event.get('requestContext', {}).get('domainName', '')
        path = event.get('requestContext', {}).get('path', '')
        if not domain or not path:
            print("Missing requestContext domain or path")
            return False
        url = f"https://{domain}{path}"
        signature = event.get('headers', {}).get('X-Twilio-Signature', '')
        body = event.get('body', '') if not event.get('isBase64Encoded', False) else base64.b64decode(event['body']).decode('utf-8')
        return validator.validate(url, urllib.parse.parse_qs(body), signature)
    except Exception as e:
        print(f"Error validating Twilio request: {str(e)}")
        publish_metric('TwilioValidationError', 1)
        return False

def publish_metric(metric_name, value, unit='Count'):
    """Publish metrics to CloudWatch."""
    try:
        cloudwatch.put_metric_data(
            Namespace='TwilioLambda',
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit
            }]
        )
    except ClientError as e:
        print(f"Error publishing metric {metric_name}: {str(e)}")

def get_existing_conversation(user_phone):
    """Checks for active conversation within timeout window."""
    cutoff_time = datetime.now() - timedelta(minutes=CONVERSATION_TIMEOUT_MINUTES)
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        try:
            response = table.query(
                IndexName='UserPhoneIndex',
                KeyConditionExpression='user_phone = :phone',
                FilterExpression='active = :active',
                ExpressionAttributeValues={
                    ':phone': user_phone,
                    ':active': True,
                    ':cutoff': int(cutoff_time.timestamp())
                }
            )
        except ClientError as e:
            if 'ValidationException' in str(e) and 'IndexName' in str(e):
                print("UserPhoneIndex not found, falling back to scan")
                response = table.scan(
                    FilterExpression='user_phone = :phone AND active = :active',
                    ExpressionAttributeValues={
                        ':phone': user_phone,
                        ':active': True,
                        ':cutoff': int(cutoff_time.timestamp())
                    }
                )
            else:
                raise
        if response.get('Items'):
            items = sorted(response['Items'], key=lambda x: x.get('last_activity', 0), reverse=True)
            for item in items:
                if item['last_activity'] <= int(cutoff_time.timestamp()):
                    table.update_item(
                        Key={'conversation_id': item['conversation_id']},
                        UpdateExpression='SET active = :active',
                        ExpressionAttributeValues={':active': False}
                    )
            return items[0]['conversation_id'] if items[0]['last_activity'] > int(cutoff_time.timestamp()) else None
        return None
    except ClientError as e:
        print(f"Error querying DynamoDB: {str(e)}")
        publish_metric('DynamoDBQueryError', 1)
        raise

def create_conversation_record(conversation_id, user_phone, channel, message_content=None):
    """Creates a new conversation record in DynamoDB."""
    print(f"CREATE_CONV_RECORD: Creating record for conversation_id: {conversation_id}")
    timestamp = int(datetime.now().timestamp())
    message_history = []
    if message_content:
        message_history.append({
            'role': 'user',
            'content': message_content,
            'timestamp': timestamp
        })
    conversation_record = {
        'conversation_id': conversation_id,
        'user_phone': user_phone,
        'channel': channel,
        'start_time': timestamp,
        'last_activity': timestamp,
        'message_history': message_history,
        'active': True
    }
    for attempt in range(3):
        try:
            table = dynamodb.Table(DYNAMODB_TABLE)
            table.put_item(Item=conversation_record)
            print(f"Created new conversation {conversation_id} in DynamoDB")
            return
        except ClientError as e:
            print(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == 2:
                publish_metric('DynamoDBWriteError', 1)
                raise Exception("Failed to store conversation in DynamoDB after retries")

def get_conversation(conversation_id):
    """Retrieves a conversation by ID from DynamoDB."""
    print(f"GET_CONVERSATION (Twilio): Querying for conversation_id: {conversation_id}")
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        response = table.get_item(Key={'conversation_id': conversation_id})
        print(f"GET_CONVERSATION (Twilio): Found item for {conversation_id}" if response.get('Item') else f"GET_CONVERSATION (Twilio): No item found for {conversation_id}")
        return response.get('Item')
    except ClientError as e:
        print(f"Error retrieving from DynamoDB: {str(e)}")
        publish_metric('DynamoDBReadError', 1)
        raise

def handle_sms_request(event, parsed_body):
    """Handles incoming SMS messages from Twilio."""
    from_number = extract_value(parsed_body, 'From') or '+1234567890'
    message_body = extract_value(parsed_body, 'Body') or 'Test message'
    print(f"SMS from: {from_number}, body: {message_body}")
    
    conversation_id = get_existing_conversation(from_number)
    if not conversation_id:
        conversation_id = str(uuid.uuid4())
        create_conversation_record(conversation_id, from_number, 'SMS', message_body)
    else:
        conversation = get_conversation(conversation_id)
        if not conversation:
            conversation_id = str(uuid.uuid4())
            create_conversation_record(conversation_id, from_number, 'SMS', message_body)
        else:
            update_conversation_with_message(conversation_id, message_body, 'user')
    
    conversation = get_conversation(conversation_id)
    ai_response = invoke_intent_handler(conversation_id, message_body, from_number, 'SMS', conversation.get('message_history', []))
    update_conversation_with_message(conversation_id, ai_response, 'assistant')
    
    resp = MessagingResponse()
    resp.message(ai_response)
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/xml'},
        'body': str(resp)
    }

def handle_voice_request(event, parsed_body):
    """Handles incoming voice calls from Twilio."""
    from_number = extract_value(parsed_body, 'From') or '+1234567890'
    call_sid = extract_value(parsed_body, 'CallSid')

    # If CallSid is missing, it's a critical error for voice processing.
    if not call_sid:
        print("Error: CallSid not found in request. Cannot process voice call.")
        publish_metric('MissingCallSidError', 1)
        voice_response_error = VoiceResponse()
        voice_response_error.say("An error occurred with your call. Please try again later.")
        voice_response_error.hangup()
        return {
            'statusCode': 200, # Twilio expects a 200 OK with TwiML
            'headers': {'Content-Type': 'text/xml'},
            'body': str(voice_response_error)
        }

    # conversation_id from action URL (passed by previous Gather)
    conversation_id_from_action = event.get('queryStringParameters', {}).get('conversation_id')
    
    # Use CallSid as the primary conversation_id if not already passed in action URL
    print(f"VOICE_HANDLER: CallSid received: {call_sid}, conversation_id from action: {conversation_id_from_action}")
    current_conversation_id = conversation_id_from_action if conversation_id_from_action else call_sid
    print(f"VOICE_HANDLER: Determined current_conversation_id: {current_conversation_id}")
    
    print(f"Voice call from: {from_number}, CallSid: {call_sid}, Current Conversation ID: {current_conversation_id}")
    
    speech_result = extract_value(parsed_body, 'SpeechResult')
    voice_response = VoiceResponse()
    
    if speech_result and speech_result.strip():
        print(f"VOICE_HANDLER: Processing SpeechResult for conversation_id: {current_conversation_id}")
        print(f"Received speech: {speech_result} for conversation {current_conversation_id}")
        # Ensure conversation record exists (it should if Gather was set up correctly)
        # If not, it implies an issue or an unexpected state, create it to be safe.
        conversation_check = get_conversation(current_conversation_id)
        if not conversation_check:
            print(f"Warning: Conversation record {current_conversation_id} not found despite SpeechResult. Creating one.")
            create_conversation_record(current_conversation_id, from_number, 'Voice', speech_result) # Add speech as first user message
        else:
            update_conversation_with_message(current_conversation_id, speech_result, 'user')
        
        conversation = get_conversation(current_conversation_id) # Re-fetch to get message_history for intent handler
        ai_response = invoke_intent_handler(current_conversation_id, speech_result, from_number, 'Voice', conversation.get('message_history', []))
        update_conversation_with_message(current_conversation_id, ai_response, 'assistant')
        
        voice_response.say(ai_response)
        gather = voice_response.gather(
            input='speech',
            action=f"?conversation_id={current_conversation_id}", # Pass current_conversation_id
            method='POST',
            speech_timeout='auto',
            language=SPEECH_LANGUAGE
        )
    else:
        # No speech result: this means it's the initial call or a gather timeout.
        print(f"VOICE_HANDLER: No SpeechResult. Attempting to get conversation for: {current_conversation_id}")
        existing_conversation = get_conversation(current_conversation_id)
        if not existing_conversation:
            # This is a new call (current_conversation_id is call_sid and no record exists)
            print(f"VOICE_HANDLER: No existing conversation found for {current_conversation_id} (CallSid: {call_sid}). Creating new record.")
            # create_conversation_record will log its own activity
            create_conversation_record(current_conversation_id, from_number, 'Voice')
            greeting = "Hello, I'm Lia, your virtual assistant. How can I help you today?"
            # Say greeting before gathering
            voice_response.say(greeting) 
            print(f"VOICE_HANDLER: Setting Gather action URL with conversation_id: {current_conversation_id}")
            gather = voice_response.gather(
                input='speech',
                action=f"?conversation_id={current_conversation_id}", # Pass current_conversation_id
                method='POST',
                speech_timeout='auto',
                language=SPEECH_LANGUAGE
            )
            # No gather.say() here as we've already greeted.
        else:
            # Existing conversation, but no speech input (e.g., gather timeout on an ongoing call)
            print(f"VOICE_HANDLER: Found existing conversation for {current_conversation_id}, but no speech input. Prompting again.")
            re_prompt_message = "I didn't catch that. Could you please say it again?"
            voice_response.say(re_prompt_message) 
            print(f"VOICE_HANDLER: Setting Gather action URL with conversation_id: {current_conversation_id}")
            gather = voice_response.gather(
                input='speech',
                action=f"?conversation_id={current_conversation_id}", # Pass current_conversation_id
                method='POST',
                speech_timeout='auto',
                language=SPEECH_LANGUAGE
            )
            # No gather.say() here as we've already re-prompted.
            
    # Fallback if no gather was added to the response.
    # This ensures Twilio doesn't get an empty response if logic above fails to add a Gather.
    if "<Gather" not in str(voice_response):
        print("Warning: No Gather verb found in TwiML response. Adding fallback hangup.")
        # Adding a say before hangup, in case no say was added either.
        if not voice_response.verbs: # Check if there are no verbs at all
             voice_response.say("I'm sorry, there was an issue processing your request. Please call back later.")
        voice_response.hangup()

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/xml'},
        'body': str(voice_response)
    }

def extract_value(parsed_body, key):
    """Extracts values from parsed body, handling different formats."""
    if not parsed_body or not isinstance(parsed_body, dict):
        return None
    value = parsed_body.get(key)
    if isinstance(value, list):
        return value[0] if value and value[0] else None
    return value

def update_conversation_with_message(conversation_id, message, role):
    """Updates conversation with a new message in DynamoDB."""
    timestamp = int(datetime.now().timestamp())
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        response = table.get_item(Key={'conversation_id': conversation_id})
        if 'Item' not in response:
            print(f"Warning: Conversation {conversation_id} not found in DynamoDB for update_conversation_with_message")
            # Optionally, create the record if it's critical that messages are stored even if initial creation failed.
            # For now, just log and return if no record to update.
            return
        conversation = response['Item']
        message_history = conversation.get('message_history', [])
        message_history.append({
            'role': role,
            'content': message,
            'timestamp': timestamp
        })
        table.update_item(
            Key={'conversation_id': conversation_id},
            UpdateExpression='SET message_history = :messages, last_activity = :time, active = :active_status',
            ExpressionAttributeValues={
                ':messages': message_history,
                ':time': timestamp,
                ':active_status': True # Ensure conversation is marked active on message update
            }
        )
        print(f"Updated conversation {conversation_id} in DynamoDB")
    except ClientError as e:
        print(f"Error updating DynamoDB: {str(e)}")
        publish_metric('DynamoDBWriteError', 1)
        raise

def invoke_intent_handler(conversation_id, message, user_id, channel, message_history):
    """Invokes the intent handler Lambda with conversation history."""
    print(f"INVOKE_INTENT_HANDLER: Invoking with conversation_id: {conversation_id}")
    try:
        payload = {
            "text": message,
            "conversation_id": conversation_id,
            "user_id": user_id,
            "channel": channel,
            "message_history": message_history
        }
        print(f"Sending payload to Intent Handler: {json.dumps(payload)}")
        response = lambda_client.invoke(
            FunctionName=INTENT_HANDLER_LAMBDA,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        response_payload = json.loads(response['Payload'].read().decode())
        print(f"Raw Intent Handler response: {json.dumps(response_payload)}")
        if response_payload.get('statusCode') == 200:
            response_body = json.loads(response_payload.get('body', '{}'))
            if 'message' in response_body and isinstance(response_body['message'], str):
                return response_body['message']
            print(f"Invalid response format from Intent Handler: {response_payload}")
            publish_metric('IntentHandlerInvalidResponse', 1)
            return "Could you please rephrase or provide more details?"
        print(f"Intent Handler error: {response_payload}")
        publish_metric('IntentHandlerFailure', 1)
        return "Could you please rephrase or provide more details?"
    except ClientError as e:
        print(f"Error invoking Intent Handler: {str(e)}")
        import traceback
        print(traceback.format_exc())
        publish_metric('IntentHandlerError', 1)
        return "I'm having technical difficulties. Please try again later."

def lambda_handler(event, context):
    """Main Lambda handler function."""
    print(f"Received event: {json.dumps(event)}")
    if not validate_twilio_request(event):
        print("Twilio request validation failed")
        publish_metric('TwilioValidationFailure', 1)
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'Invalid Twilio request'})
        }
    
    parsed_body = parse_request_body(event)
    print(f"Final parsed_body: {json.dumps(parsed_body)}")
    is_voice = is_voice_request(parsed_body, event)
    
    try:
        if is_voice:
            print("Processing as voice call")
            return handle_voice_request(event, parsed_body)
        else:
            print("Processing as SMS")
            return handle_sms_request(event, parsed_body)
    except Exception as e:
        error_id = str(uuid.uuid4())
        print(f"Error ID {error_id}: {str(e)}")
        import traceback
        print(traceback.format_exc())
        publish_metric('RequestProcessingError', 1)
        error_message = f"Sorry, an error occurred (ID: {error_id}). Please try again or contact support."
        if is_voice:
            resp = VoiceResponse()
            resp.say(error_message)
            resp.hangup()
        else:
            resp = MessagingResponse()
            resp.message(error_message)
        return {
            'statusCode': 200, # Twilio expects 200 for TwiML responses
            'headers': {'Content-Type': 'text/xml'},
            'body': str(resp)
        }

def parse_request_body(event):
    """Parses request body with strict validation."""
    if not event.get('body'):
        print("Error: No body in event")
        return {}
    body_str = event['body']
    if event.get('isBase64Encoded', False):
        try:
            body_str = base64.b64decode(body_str).decode('utf-8')
        except Exception as e:
            print(f"Error decoding base64 body: {str(e)}")
            publish_metric('Base64DecodeError', 1)
            return {}
    try:
        return urllib.parse.parse_qs(body_str)
    except Exception as e:
        print(f"Error parsing body as form data: {str(e)}")
        publish_metric('BodyParseError', 1)
        return {}

def is_voice_request(parsed_body, event):
    """Determines if the request is for voice or SMS."""
    # Check if CallSid is in parsed_body, which is typical for voice calls.
    # Also, check if 'SpeechResult' is present or if it's a GET request to the base path (initial call).
    # This helps differentiate from SMS which are POSTs without CallSid in the same way.
    if isinstance(parsed_body, dict) and 'CallSid' in parsed_body:
        return True
    # Check for path often associated with voice calls if other indicators are missing.
    # This part might be too specific or need adjustment based on actual deployment.
    # if event.get('rawPath') == '/LiaAgentPROD': # Example, adjust as needed
    #    return True
    return False
