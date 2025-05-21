"""
Updated Twilio Input Handler Lambda with Intent Recognition Integration
- Fixed chat loop functionality for SMS and voice conversations
- Enhanced DynamoDB persistence with cleanup for expired conversations
- Improved error handling, logging, and Twilio validation
- Removed in-memory storage reliance
- Added metrics for monitoring
- Fixed DynamoDB index, CallSid mapping, and request validation errors

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
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        response = table.get_item(Key={'conversation_id': conversation_id})
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
    conversation_id = extract_value(parsed_body, 'conversation_id') or \
                     (event.get('queryStringParameters', {}).get('conversation_id') if event.get('queryStringParameters') else None)
    
    print(f"Voice call from: {from_number}, CallSid: {call_sid}, Conversation ID: {conversation_id}")
    
    if call_sid and not conversation_id:
        try:
            table = dynamodb.Table(DYNAMODB_TABLE)
            response = table.get_item(Key={'conversation_id': call_sid})
            if 'Item' in response and 'mapped_conversation_id' in response['Item']:
                conversation_id = response['Item']['mapped_conversation_id']
                if not get_conversation(conversation_id):
                    conversation_id = str(uuid.uuid4())
                    create_conversation_record(conversation_id, from_number, 'Voice')
                    table.update_item(
                        Key={'conversation_id': call_sid},
                        UpdateExpression='SET mapped_conversation_id = :cid',
                        ExpressionAttributeValues={':cid': conversation_id}
                    )
            else:
                conversation_id = str(uuid.uuid4())
                create_conversation_record(conversation_id, from_number, 'Voice')
                table.put_item(Item={'conversation_id': call_sid, 'mapped_conversation_id': conversation_id})
        except ClientError as e:
            print(f"Error mapping CallSid: {str(e)}")
            publish_metric('DynamoDBWriteError', 1)
            conversation_id = str(uuid.uuid4())
            create_conversation_record(conversation_id, from_number, 'Voice')
    
    speech_result = extract_value(parsed_body, 'SpeechResult')
    voice_response = VoiceResponse()
    
    if speech_result and speech_result.strip():
        print(f"Received speech: {speech_result}")
        update_conversation_with_message(conversation_id, speech_result, 'user')
        conversation = get_conversation(conversation_id)
        ai_response = invoke_intent_handler(conversation_id, speech_result, from_number, 'Voice', conversation.get('message_history', []))
        update_conversation_with_message(conversation_id, ai_response, 'assistant')
        
        voice_response.say(ai_response)
        gather = voice_response.gather(
            input='speech',
            action=f"?conversation_id={conversation_id}",
            method='POST',
            speech_timeout='auto',
            language=SPEECH_LANGUAGE
        )
    else:
        greeting = "Hello, I'm Lia, your virtual assistant. How can I help you today?"
        gather = voice_response.gather(
            input='speech',
            action=f"?conversation_id={conversation_id}",
            method='POST',
            speech_timeout='auto',
            language=SPEECH_LANGUAGE
        )
        gather.say(greeting)
    
    voice_response.say("I didn't hear anything. Please call back when you're ready.")
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
            print(f"Warning: Conversation {conversation_id} not found in DynamoDB")
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
            UpdateExpression='SET message_history = :messages, last_activity = :time',
            ExpressionAttributeValues={
                ':messages': message_history,
                ':time': timestamp
            }
        )
        print(f"Updated conversation {conversation_id} in DynamoDB")
    except ClientError as e:
        print(f"Error updating DynamoDB: {str(e)}")
        publish_metric('DynamoDBWriteError', 1)
        raise

def invoke_intent_handler(conversation_id, message, user_id, channel, message_history):
    """Invokes the intent handler Lambda with conversation history."""
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
            'statusCode': 200,
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
    if isinstance(parsed_body, dict) and 'CallSid' in parsed_body:
        return True
    return False
