"""
Updated Twilio Input Handler Lambda with Intent Recognition Integration

This Lambda function handles incoming Twilio SMS and voice calls, now integrated with
the Intent Handler Lambda to provide more intelligent responses.

Date: May 2025
"""

import json
import os
import uuid
import time
from datetime import datetime, timedelta
import urllib.parse
import boto3
from twilio.request_validator import RequestValidator
from twilio.twiml.voice_response import VoiceResponse
from twilio.twiml.messaging_response import MessagingResponse

# In-memory storage for POC (resets when Lambda cold starts)
active_conversations = {}

# Simplified configuration
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '7eecd1171f814d9fdfad9daf4bd778c6')
# Chandra account '8057d8ebbc836d46e6f339c602642dd8')
CONVERSATION_TIMEOUT_MINUTES = 30
INTENT_HANDLER_LAMBDA = os.environ.get('INTENT_HANDLER_LAMBDA', 'GAMMAFIntentHandler')

# Initialize Lambda client
lambda_client = boto3.client('lambda')

def validate_twilio_request(event):
    """
    Validates that requests are coming from Twilio.
    Returns True if valid, False otherwise.
    """
    # For direct Lambda testing or during development, bypass validation
    # IMPORTANT: Remove this in production!
    print("Bypassing Twilio validation for POC")
    return True
    
    # The validation code below is kept for reference but bypassed for POC simplicity
    # To enable validation, remove the return True above
    
    # For direct Lambda testing, bypass validation
    if not event.get('headers') or not event.get('requestContext'):
        print("Event doesn't have expected API Gateway format, bypassing validation")
        return True
    
    validator = RequestValidator(TWILIO_AUTH_TOKEN)
    
    try:
        # Extract request details from API Gateway event
        url = f"https://{event['headers'].get('Host', 'localhost')}{event['requestContext'].get('path', '')}"
        
        # Get signature from headers
        signature = event['headers'].get('X-Twilio-Signature')
        if not signature:
            print("No Twilio signature found in headers")
            # For testing purposes, you might want to return True here instead
            return False
        
        # For POST requests, validate the form parameters
        if event.get('httpMethod') == 'POST':
            params = {}
            if event.get('body'):
                body_str = event['body']
                # If body is base64 encoded (common with binary types)
                if event.get('isBase64Encoded', False):
                    import base64
                    body_str = base64.b64decode(body_str).decode('utf-8')
                params = urllib.parse.parse_qs(body_str)
                # Convert list values to single values for validation
                params = {k: v[0] for k, v in params.items()}
            
            return validator.validate(url, params, signature)
    except Exception as e:
        print(f"Error during validation: {str(e)}")
        # For testing purposes, return True to bypass validation
        return True
    
    return False

def get_existing_conversation(user_phone):
    """
    Checks if there's an active conversation for this user within the timeout window.
    Returns conversation_id if found, None otherwise.
    """
    cutoff_time = datetime.now() - timedelta(minutes=CONVERSATION_TIMEOUT_MINUTES)
    
    # Look for active conversations for this user
    for conv_id, conv_data in active_conversations.items():
        if (conv_data['user_phone'] == user_phone and 
            conv_data['active'] and
            datetime.fromtimestamp(conv_data['last_activity']) > cutoff_time):
            return conv_id
    
    return None

def create_conversation_record(conversation_id, user_phone, channel, message_content=None):
    """
    Creates a new conversation record in memory.
    """
    timestamp = int(datetime.now().timestamp())
    
    # Initialize message history if we have content
    message_history = []
    if message_content:
        message_history.append({
            'role': 'user',
            'content': message_content,
            'timestamp': timestamp
        })
    
    # Create the conversation record in memory
    active_conversations[conversation_id] = {
        'conversation_id': conversation_id,
        'user_phone': user_phone,
        'channel': channel,
        'start_time': timestamp,
        'last_activity': timestamp,
        'message_history': message_history,
        'active': True
    }

def handle_sms_request(event, parsed_body):
    """
    Handles incoming SMS messages from Twilio.
    """
    # Extract SMS details - handle both direct dict and parse_qs format
    from_number = None
    to_number = None
    message_body = None
    
    # Handle different possible formats of parsed_body
    if isinstance(parsed_body, dict):
        # Extract from_number
        if 'From' in parsed_body:
            if isinstance(parsed_body['From'], list):
                from_number = parsed_body['From'][0]
            else:
                from_number = parsed_body['From']
        
        # Extract to_number
        if 'To' in parsed_body:
            if isinstance(parsed_body['To'], list):
                to_number = parsed_body['To'][0]
            else:
                to_number = parsed_body['To']
                
        # Extract message_body
        if 'Body' in parsed_body:
            if isinstance(parsed_body['Body'], list):
                message_body = parsed_body['Body'][0]
            else:
                message_body = parsed_body['Body']
    
    # Log extracted values
    print(f"SMS from: {from_number}, to: {to_number}, body: {message_body}")
    
    # If from_number is still None, use a default for testing
    if from_number is None:
        from_number = '+1234567890'
        print(f"Using default from_number: {from_number}")
    
    # If message_body is still None, use a default for testing
    if message_body is None:
        message_body = 'Test message'
        print(f"Using default message_body: {message_body}")
    
    # Check for existing conversation
    conversation_id = get_existing_conversation(from_number)
    
    # If no existing conversation, create a new one
    if not conversation_id:
        conversation_id = str(uuid.uuid4())
        create_conversation_record(conversation_id, from_number, 'SMS', message_body)
        print(f"Created new conversation {conversation_id}")
    else:
        # Update existing conversation with new message
        update_conversation_with_message(conversation_id, message_body, 'user')
        print(f"Updated existing conversation {conversation_id}")
    
    # Generate a response using the Intent Handler Lambda
    ai_response = invoke_intent_handler(conversation_id, message_body, from_number, 'SMS')
    update_conversation_with_message(conversation_id, ai_response, 'assistant')
    
    # Return response to user
    return create_simple_response("SMS", ai_response)

def handle_voice_request(event, parsed_body):
    """
    Handles incoming voice calls from Twilio.
    """
    # Extract voice call details - handle both direct dict and parse_qs format
    from_number = None
    call_sid = None
    conversation_id = None
    
    # Handle different possible formats of parsed_body
    if isinstance(parsed_body, dict):
        # Extract from_number
        if 'From' in parsed_body:
            if isinstance(parsed_body['From'], list):
                from_number = parsed_body['From'][0]
            else:
                from_number = parsed_body['From']
        
        # Extract call_sid
        if 'CallSid' in parsed_body:
            if isinstance(parsed_body['CallSid'], list):
                call_sid = parsed_body['CallSid'][0]
            else:
                call_sid = parsed_body['CallSid']
                
        # Extract conversation_id
        if 'conversation_id' in parsed_body:
            if isinstance(parsed_body['conversation_id'], list):
                conversation_id = parsed_body['conversation_id'][0]
            else:
                conversation_id = parsed_body['conversation_id']
    
    # Also check queryStringParameters for conversation_id
    if event.get('queryStringParameters') and event['queryStringParameters'].get('conversation_id'):
        conversation_id = event['queryStringParameters']['conversation_id']
    
    # Log extracted values
    print(f"Voice call from: {from_number}, CallSid: {call_sid}, Conversation ID: {conversation_id}")
    
    # If from_number is still None, use a default for testing
    if from_number is None:
        from_number = '+1234567890'
        print(f"Using default from_number: {from_number}")
    
    # If no conversation_id provided, this is a new call
    if not conversation_id:
        conversation_id = str(uuid.uuid4())
        create_conversation_record(conversation_id, from_number, 'Voice')
        print(f"Created new voice conversation {conversation_id}")
    
    # Check if we have transcribed speech
    speech_result = None
    if isinstance(parsed_body, dict) and 'SpeechResult' in parsed_body:
        if isinstance(parsed_body['SpeechResult'], list):
            speech_result = parsed_body['SpeechResult'][0]
        else:
            speech_result = parsed_body['SpeechResult']
    
    # If we have speech, process it
    if speech_result:
        print(f"Received speech: {speech_result}")
        update_conversation_with_message(conversation_id, speech_result, 'user')
        
        # Generate a response using the Intent Handler Lambda
        ai_response = invoke_intent_handler(conversation_id, speech_result, from_number, 'Voice')
        update_conversation_with_message(conversation_id, ai_response, 'assistant')
        
        # Return response to user
        voice_response = VoiceResponse()
        voice_response.say(ai_response)
        
        # Listen for more input
        gather = voice_response.gather(
            input='speech',
            action=f"?conversation_id={conversation_id}",
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        
        # Add a fallback
        voice_response.say("I didn't hear anything. Goodbye.")
        voice_response.hangup()
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/xml'},
            'body': str(voice_response)
        }
    else:
        # Initial greeting for voice call
        voice_response = VoiceResponse()
        
        # Use a default greeting instead of calling intent handler for initial welcome
        greeting = "Hello, I'm Lia, your virtual assistant. How can I help you today?"
        
        # Add the greeting and listen for user input
        gather = voice_response.gather(
            input='speech',
            action=f"?conversation_id={conversation_id}",
            method='POST',
            speech_timeout='auto',
            language='en-US'
        )
        gather.say(greeting)
        
        # Add a fallback in case the user doesn't speak
        voice_response.say("I didn't hear anything. Please call back when you're ready.")
        voice_response.hangup()
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/xml'},
            'body': str(voice_response)
        }

def update_conversation_with_message(conversation_id, message, role):
    """
    Updates an existing conversation with a new message.
    """
    if conversation_id not in active_conversations:
        print(f"Warning: Conversation {conversation_id} not found")
        return
    
    timestamp = int(datetime.now().timestamp())
    
    # Add message to history
    active_conversations[conversation_id]['message_history'].append({
        'role': role,
        'content': message,
        'timestamp': timestamp
    })
    
    # Update last activity timestamp
    active_conversations[conversation_id]['last_activity'] = timestamp

def invoke_intent_handler(conversation_id, message, user_id, channel, additional_context=None):
    try:
        # Prepare payload for Intent Handler Lambda
        payload = {
       
                                             
                             
    
                                             
                                                                             
    
            "text": message,
            "conversation_id": conversation_id,
            "user_id": user_id,
            "channel": channel
        }
        
        if additional_context:
            payload["additional_context"] = additional_context
        
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
            return response_body.get('message', "Default response from intent handler")
        else:
            print(f"Intent Handler error: {response_payload}")
            return "I'm sorry, but I'm having trouble understanding. Could you try again?"
            
    except Exception as e:
        print(f"Error invoking Intent Handler: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return "I'm having technical difficulties. Please try again later."
        
def create_simple_response(channel_type, message=None):
    """
    Creates a simple Twilio response based on the channel type.
    """
    if channel_type == "SMS":
        resp = MessagingResponse()
        if message:
            resp.message(message)
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/xml'},
            'body': str(resp)
        }
    else:  # Voice
        resp = VoiceResponse()
        if message:
            resp.say(message)
            resp.hangup()
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/xml'},
            'body': str(resp)
        }

def lambda_handler(event, context):
    """
    Main Lambda handler function.
    """
    # Log the incoming event for debugging
    print(f"Received event: {json.dumps(event)}")
    
    # Check if event has expected structure from API Gateway
    is_api_gateway_event = 'headers' in event and 'requestContext' in event
    
    # Parse the request body
    parsed_body = {}
    if event.get('body'):
        body_str = event['body']
        
        # Handle base64 encoded bodies (common with binary media types)
        if event.get('isBase64Encoded', False):
            import base64
            try:
                body_str = base64.b64decode(body_str).decode('utf-8')
                print(f"Decoded base64 body: {body_str[:200]}...")  # Log first 200 chars
            except Exception as e:
                print(f"Error decoding base64 body: {str(e)}")
        
        try:
            # Try to parse as formრ

            # Try to parse as form data
            parsed_body = urllib.parse.parse_qs(body_str)
            print(f"Parsed body as form data: {json.dumps(parsed_body)}")
        except Exception as e:
            print(f"Error parsing body as form data: {str(e)}")
            # If form parsing fails, try JSON
            try:
                parsed_body = json.loads(body_str)
                # Convert to same format as parse_qs for consistency
                if isinstance(parsed_body, dict):
                    parsed_body = {k: [v] for k, v in parsed_body.items()}
                print(f"Parsed body as JSON: {json.dumps(parsed_body)}")
            except Exception as e:
                print(f"Error parsing body as JSON: {str(e)}")
    
    # Try direct access if structured parsing failed
    if not parsed_body and isinstance(event, dict):
        # Just use the event directly, in case body parsing failed
        parsed_body = event
    
    # For debugging, log what we received
    print(f"Final parsed_body: {json.dumps(parsed_body)}")
    
    # Determine if this is SMS or Voice based on presence of CallSid
    is_voice = False
    
    # Check in parsed_body if it's a dict with items
    if isinstance(parsed_body, dict) and parsed_body:
        is_voice = 'CallSid' in parsed_body
    
    # Also check first level of lists if present
    if isinstance(parsed_body, dict):
        for key, value in parsed_body.items():
            if isinstance(value, list) and value and key == 'CallSid':
                is_voice = True
                break
    
    # For direct testing, override with query parameters if present
    if event.get('queryStringParameters') and event['queryStringParameters'].get('test_mode'):
        test_mode = event['queryStringParameters'].get('test_mode')
        if test_mode == 'voice':
            is_voice = True
            parsed_body = {'CallSid': ['test_call'], 'From': ['+1234567890']}
        elif test_mode == 'sms':
            is_voice = False
            parsed_body = {'MessageSid': ['test_msg'], 'From': ['+1234567890'], 'Body': ['Hello World']}
    
    try:
        if is_voice:
            print("Processing as voice call")
            return handle_voice_request(event, parsed_body)
        else:
            print("Processing as SMS")
            return handle_sms_request(event, parsed_body)
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        import traceback
        print(traceback.format_exc())
        
        # Return a generic error response
        if is_voice:
            resp = VoiceResponse()
            resp.say("I'm sorry, but we're experiencing technical difficulties. Please try again later.")
            resp.hangup()
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'text/xml'},
                'body': str(resp)
            }
        else:
            resp = MessagingResponse()
            resp.message("I'm sorry, but we're experiencing technical difficulties. Please try again later.")
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'text/xml'},
                'body': str(resp)
            }