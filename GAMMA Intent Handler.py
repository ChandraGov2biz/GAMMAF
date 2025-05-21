"""
Intent Handler Lambda for Lia AI Agent - Fixed for Chat Loop Persistence
- Improved intent recognition with conversation history
- Enhanced error handling and fallback mechanisms
- Optimized DynamoDB interactions
- Added metrics for monitoring
- Fixed Bedrock response parsing, endpoint processing, and model ID alignment
- Ensured CallSid is used as conversation_id for new voice call records in DynamoDB

Date: May 2025
"""

import json
import os
import boto3
import uuid
import time
import logging
from botocore.exceptions import ClientError
import requests

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE','LiaAgentConversations')
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-haiku-20240307-v1:0')
BEDROCK_REGION = os.environ.get('BEDROCK_REGION', 'us-east-2')

# Agent capabilities configuration
AGENT_CAPABILITIES = {
    "knowledge_base": {
        "description": "Answers general questions about the agency, services, policies, and procedures.",
        "endpoint": "https://0u3v3asjsl.execute-api.us-east-2.amazonaws.com/dev/chat",
        "method": "POST",
        "required_params": ["query"],
        "confidence_threshold": 0.7,
        "knowledge_base_id": "U5XDMVS9KM",
        "knowledge_base_region": "us-east-2",
        "inference_profile_arn": f"arn:aws:bedrock:us-east-2:203918860835:inference-profile/{BEDROCK_MODEL_ID}"
    },
    "payment_inquiry": {
        "description": "Handles inquiries about payment amounts, due dates, and payment history.",
        "endpoint": "TO_BE_CONFIGURED_GOVCRAFT_API",
        "method": "POST",
        "required_params": ["account_number", "verification_info"],
        "required_context": ["account_number", "customer_name"],
        "confidence_threshold": 0.75
    },
    "appointment_scheduling": {
        "description": "Helps schedule, reschedule, or cancel appointments.",
        "endpoint": "TO_BE_CONFIGURED_APPOINTMENT_API",
        "method": "POST",
        "required_params": ["date", "time", "purpose"],
        "required_context": ["account_number", "customer_name"],
        "confidence_threshold": 0.75
    },
    "general_greeting": {
        "description": "Handles general greetings and introductions.",
        "response_template": "Hello! I'm Lia, your virtual assistant. I can help you with information about our agency, check payment details, or schedule appointments. How can I assist you today?",
        "confidence_threshold": 0.6
    }
}

# Initialize AWS clients
try:
    bedrock_runtime = boto3.client('bedrock-runtime', region_name=BEDROCK_REGION)
    bedrock_agent_runtime = boto3.client('bedrock-agent-runtime', region_name=BEDROCK_REGION)
    dynamodb = boto3.resource('dynamodb')
    cloudwatch = boto3.client('cloudwatch')
    logger.info("Successfully connected to AWS services")
except Exception as e:
    logger.error(f"Error connecting to AWS services: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())
    bedrock_runtime = None
    bedrock_agent_runtime = None
    dynamodb = None
    cloudwatch = None

def validate_environment():
    """Validate required environment variables."""
    required_vars = ['DYNAMODB_TABLE']
    for var in required_vars:
        if not os.environ.get(var):
            raise EnvironmentError(f"Missing required environment variable: {var}")

validate_environment()

def publish_metric(metric_name, value, unit='Count'):
    """Publish metrics to CloudWatch."""
    try:
        cloudwatch.put_metric_data(
            Namespace='IntentHandler',
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit
            }]
        )
    except ClientError as e:
        logger.error(f"Error publishing metric {metric_name}: {str(e)}")

def lambda_handler(event, context):
    """Main handler for the Intent Recognition Lambda."""
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        user_input = event.get('text', '')
        conversation_id = event.get('conversation_id') # This will be CallSid for new voice calls
        logger.info(f"GAMMA_HANDLER: Received event with conversation_id: {conversation_id}")
        user_id = event.get('user_id', 'unknown_user')
        channel = event.get('channel', 'unknown')
        message_history = event.get('message_history', [])
        if not isinstance(message_history, list):
            logger.warning("Invalid message_history format, using empty list")
            publish_metric('InvalidMessageHistory', 1)
            message_history = []
        
        if not user_input:
            publish_metric('MissingInputError', 1)
            return format_response(False, "Missing required parameter: text", 400)
        
        # get_conversation_state will now use the passed conversation_id (CallSid)
        # for new records if it's provided and not found, or generate a UUID if it's None.
        conversation_state = get_conversation_state(conversation_id, user_id, channel)
        # The conversation_id used for the rest of this lambda execution
        # will be the one from conversation_state (either the original CallSid or a new UUID).
        current_conversation_id_in_handler = conversation_state['conversation_id']
        
        add_message_to_history(current_conversation_id_in_handler, "user", user_input)
        conversation_history = get_conversation_history(current_conversation_id_in_handler)
        
        if is_likely_knowledge_query(user_input):
            logger.info(f"Query '{user_input}' identified as likely knowledge query")
            return format_response(True, handle_knowledge_base_intent(current_conversation_id_in_handler, {}, user_input))
        
        current_internal_state = conversation_state.get('state', 'initial') # Renamed to avoid confusion
        pending_intent = conversation_state.get('pending_intent')
        
        if current_internal_state != 'initial' and pending_intent:
            response = continue_conversation(
                current_conversation_id_in_handler, user_input, current_internal_state, pending_intent, conversation_history
            )
        else:
            response = identify_and_process_intent(
                current_conversation_id_in_handler, user_input, conversation_history
            )
        
        return format_response(True, response)
    except Exception as e:
        error_id = str(uuid.uuid4())
        logger.error(f"Error ID {error_id}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        publish_metric('LambdaHandlerError', 1)
        return format_response(False, f"Internal server error (ID: {error_id})", 500)

def is_likely_knowledge_query(text):
    """Heuristic to identify simple knowledge questions."""
    text = text.lower()
    location_terms = ['where', 'location', 'address', 'directions', 'map']
    time_terms = ['hour', 'time', 'when', 'open', 'close', 'schedule']
    info_terms = ['how to', 'information', 'details', 'guide', 'instruction']
    if any(term in text for term in location_terms + time_terms + info_terms) or \
       (len(text.split()) < 8 and '?' in text):
        return True
    return False

def get_conversation_state(conversation_id, user_id, channel):
    """
    Gets or creates a conversation state in DynamoDB.
    If conversation_id is provided and not found, it uses that ID for the new record.
    If conversation_id is None, it generates a new UUID.
    """
    logger.info(f"GET_CONV_STATE: Called with conversation_id: {conversation_id}")
    if conversation_id:
        conversation = get_conversation(conversation_id)
        if conversation:
            # Existing conversation found
            logger.info(f"GET_CONV_STATE: Found existing conversation for id: {conversation_id}")
            conversation['last_activity'] = int(time.time())
            update_conversation(conversation_id, {'last_activity': conversation['last_activity']})
            logger.info(f"Returning existing conversation: {conversation_id}")
            return conversation
        else:
            # Conversation ID was provided, but no record found. Use this ID for the new record.
            logger.info(f"Conversation ID '{conversation_id}' provided but not found. Will create new record with this ID.")
            id_for_new_record = conversation_id
    else:
        # No conversation_id provided (e.g., for non-voice channels or if it was None), generate a new one.
        logger.info("No conversation_id provided. Generating new UUID for new record.")
        id_for_new_record = str(uuid.uuid4())
    
    logger.info(f"GET_CONV_STATE: Creating new conversation state with id: {id_for_new_record}")
    # Create new conversation record
    timestamp = int(time.time())
    new_conversation_data = {
        'conversation_id': id_for_new_record,
        'user_id': user_id,
        'channel': channel,
        'start_time': timestamp,
        'last_activity': timestamp,
        'state': 'initial',
        'pending_intent': None,
        'collected_info': {},
        'message_history': []  # Initialize with empty history
    }
    store_conversation(id_for_new_record, new_conversation_data)
    logger.info(f"Created new conversation with ID: {id_for_new_record}")
    return new_conversation_data

def get_conversation(conversation_id):
    """Retrieves a conversation by ID from DynamoDB."""
    logger.info(f"GET_CONVERSATION (Gamma): Querying for conversation_id: {conversation_id}")
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        response = table.get_item(Key={'conversation_id': conversation_id})
        if 'Item' in response:
            logger.info(f"Retrieved conversation {conversation_id} from DynamoDB") # Existing good log
            return response['Item']
        logger.warning(f"Conversation {conversation_id} not found in DynamoDB")
        return None
    except ClientError as e:
        logger.error(f"Error retrieving from DynamoDB: {str(e)}")
        publish_metric('DynamoDBReadError', 1)
        raise

def store_conversation(conversation_id, conversation_data):
    """Stores a conversation in DynamoDB."""
    logger.info(f"STORE_CONVERSATION: Storing data for conversation_id: {conversation_id}, Data: {json.dumps(conversation_data)}")
    for attempt in range(3):
        try:
            table = dynamodb.Table(DYNAMODB_TABLE)
            table.put_item(Item=conversation_data)
            logger.info(f"Stored conversation {conversation_id} in DynamoDB") # Existing good log
            return
        except ClientError as e:
            logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == 2:
                publish_metric('DynamoDBWriteError', 1)
                raise Exception("Failed to store conversation in DynamoDB after retries")

def update_conversation(conversation_id, updates):
    """Updates a conversation in DynamoDB."""
    logger.info(f"UPDATE_CONVERSATION: Updating conversation_id: {conversation_id} with updates: {json.dumps(updates)}")
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        update_expression = "SET " + ", ".join(f"#{k} = :{k}" for k in updates.keys())
        expression_values = {f":{k}": v for k, v in updates.items()}
        attribute_names = {f"#{k}": k for k in updates.keys()}
        table.update_item(
            Key={'conversation_id': conversation_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames=attribute_names
        )
        logger.info(f"Updated conversation {conversation_id} in DynamoDB")
    except ClientError as e:
        logger.error(f"Error updating DynamoDB: {str(e)}")
        publish_metric('DynamoDBWriteError', 1)
        raise

def add_message_to_history(conversation_id, role, message):
    """Adds a message to the conversation history in DynamoDB."""
    logger.info(f"ADD_MESSAGE_TO_HISTORY: Adding message for conversation_id: {conversation_id}, role: {role}")
    timestamp = int(time.time())
    conversation = get_conversation(conversation_id)
    if not conversation:
        # This can happen if get_conversation_state just created the record
        # but the local variable 'conversation' here is not yet updated.
        # Attempt to fetch it again.
        logger.warning(f"Initial get_conversation failed in add_message_to_history for {conversation_id}. Re-fetching.")
        conversation = get_conversation(conversation_id)
        if not conversation:
            logger.error(f"Cannot add message to non-existent conversation {conversation_id} even after re-fetch.")
            return

    message_history = conversation.get('message_history', [])
    message_history.append({
        'role': role,
        'content': message,
        'timestamp': timestamp
    })
    updates = {
        'message_history': message_history,
        'last_activity': timestamp
    }
    update_conversation(conversation_id, updates)

def get_conversation_history(conversation_id, max_messages=10):
    """Gets conversation history, limited to last 'max_messages'."""
    conversation = get_conversation(conversation_id)
    if not conversation:
        logger.warning(f"Conversation {conversation_id} not found for get_conversation_history")
        return []
    history = conversation.get('message_history', [])
    return history[-max_messages:]

def update_conversation_state(conversation_id, state_updates):
    """Updates the conversation state with new values."""
    conversation = get_conversation(conversation_id)
    if not conversation:
        logger.warning(f"Conversation {conversation_id} not found for update_conversation_state")
        return
    updates = state_updates.copy()
    updates['last_activity'] = int(time.time())
    update_conversation(conversation_id, updates)

def format_capabilities_for_prompt():
    """Formats agent capabilities for inclusion in the prompt."""
    capabilities = []
    for intent, config in AGENT_CAPABILITIES.items():
        capabilities.append(f"- {intent}: {config['description']}")
    return "\n".join(capabilities)

def format_conversation_history(history):
    """Formats conversation history for the prompt."""
    if not history:
        return "No previous conversation history."
    formatted = []
    for msg in history:
        role = msg.get('role', 'unknown').capitalize()
        content = msg.get('content', '')
        formatted.append(f"{role}: {content}")
    return "\n".join(formatted)

def create_intent_recognition_prompt(user_input, capabilities_context, conversation_context):
    """Creates a prompt for Bedrock to identify user intent."""
    prompt = f"""
You are Lia, a virtual assistant for a government agency. Your capabilities include:
{capabilities_context}

Current conversation history:
{conversation_context}

User's latest input: "{user_input}"

Based on the input and conversation history, identify the user's intent from the available capabilities. Return a JSON object with:
- intent_type: The identified intent (e.g., "knowledge_base", "payment_inquiry")
- confidence: A float between 0 and 1 indicating confidence in the intent
- entities: A dictionary of extracted entities (e.g., {"account_number": "12345"})
- required_info: A list of any additional information needed to fulfill the intent

If no clear intent is identified, return an empty intent_type and suggest clarification.
"""
    return [{"role": "user", "content": prompt}]

def call_bedrock_model(messages):
    """Calls Amazon Bedrock to process the prompt."""
    if not bedrock_runtime:
        logger.error("Bedrock runtime not initialized")
        publish_metric('BedrockNotInitialized', 1)
        return None
    try:
        response = bedrock_runtime.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType='application/json',
            accept='application/json',
            body=json.dumps({
                "messages": messages,
                "max_tokens": 500,
                "temperature": 0.7
            })
        )
        response_body = json.loads(response['body'].read().decode())
        return response_body.get('content', [{}])[0].get('text', '')
    except ClientError as e:
        logger.error(f"Error calling Bedrock: {str(e)}")
        publish_metric('BedrockCallError', 1)
        return None

def parse_intent_response(response_text):
    """Parses the Bedrock response to extract intent details."""
    if not response_text:
        logger.error("Empty Bedrock response")
        publish_metric('BedrockEmptyResponse', 1)
        raise ValueError("Empty response from Bedrock")
    try:
        return json.loads(response_text)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing Bedrock response: {str(e)}")
        publish_metric('BedrockParseError', 1)
        raise ValueError("Invalid JSON response from Bedrock")

def handle_knowledge_base_intent(conversation_id, entities, user_input):
    """Handles knowledge base queries using Bedrock Agent."""
    if not bedrock_agent_runtime:
        logger.error("Bedrock Agent runtime not initialized")
        publish_metric('BedrockAgentNotInitialized', 1)
        return "I'm unable to process your request at this time."
    try:
        response = bedrock_agent_runtime.retrieve_and_generate(
            input={'text': user_input},
            retrieveAndGenerateConfiguration={
                'type': 'KNOWLEDGE_BASE',
                'knowledgeBaseConfiguration': {
                    'knowledgeBaseId': AGENT_CAPABILITIES['knowledge_base']['knowledge_base_id'],
                    'modelArn': AGENT_CAPABILITIES['knowledge_base']['inference_profile_arn']
                }
            }
        )
        answer = response['output']['text']
        add_message_to_history(conversation_id, "assistant", answer)
        return answer
    except ClientError as e:
        logger.error(f"Error querying knowledge base: {str(e)}")
        publish_metric('KnowledgeBaseError', 1)
        return "I'm sorry, I couldn't find that information. Could you try asking differently?"

def continue_conversation(conversation_id, user_input, current_state, pending_intent, conversation_history):
    """Continues a multi-turn conversation by collecting required info."""
    conversation = get_conversation(conversation_id)
    if not conversation:
        logger.warning(f"Conversation {conversation_id} not found for continue_conversation")
        return "I'm sorry, something went wrong. Let's start over. How can I help you?"
    
    collected_info = conversation.get('collected_info', {})
    required_info = conversation.get('required_info', [])
    
    if not required_info:
        return process_intent(conversation_id, pending_intent, collected_info, user_input)
    
    next_info = required_info[0]
    collected_info[next_info] = user_input
    required_info.pop(0)
    
    update_conversation_state(conversation_id, {
        'collected_info': collected_info,
        'required_info': required_info,
        'state': 'collecting_info' if required_info else 'ready'
    })
    
    if required_info:
        next_prompt = f"Thank you! Now, please provide your {required_info[0].replace('_', ' ')}."
        add_message_to_history(conversation_id, "assistant", next_prompt)
        return next_prompt
    
    return process_intent(conversation_id, pending_intent, collected_info, user_input)

def process_intent(conversation_id, intent_type, entities, user_input):
    """Processes the identified intent."""
    capability = AGENT_CAPABILITIES[intent_type]
    if intent_type == "general_greeting":
        response = capability['response_template']
        add_message_to_history(conversation_id, "assistant", response)
        return response
    elif intent_type == "knowledge_base":
        return handle_knowledge_base_intent(conversation_id, entities, user_input)
    else:
        endpoint = capability.get('endpoint')
        method = capability.get('method', 'POST')
        required_params = capability.get('required_params', [])
        if not all(param in entities for param in required_params):
            response = f"Missing required parameters for {intent_type.replace('_', ' ')}."
            add_message_to_history(conversation_id, "assistant", response)
            return response
        try:
            payload = {param: entities.get(param) for param in required_params}
            response = requests.request(method, endpoint, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json().get('result', f"Processed {intent_type.replace('_', ' ')} successfully")
            add_message_to_history(conversation_id, "assistant", result)
            return result
        except requests.RequestException as e:
            logger.error(f"Error calling {intent_type} endpoint: {str(e)}")
            publish_metric(f"{intent_type}EndpointError", 1)
            response = f"Sorry, I couldn't process your {intent_type.replace('_', ' ')} request. Please try again."
            add_message_to_history(conversation_id, "assistant", response)
            return response

def identify_and_process_intent(conversation_id, user_input, conversation_history):
    """Identifies and processes intent using Bedrock."""
    capabilities_context = format_capabilities_for_prompt()
    conversation_context = format_conversation_history(conversation_history)
    messages = create_intent_recognition_prompt(user_input, capabilities_context, conversation_context)
    
    intent_response = call_bedrock_model(messages)
    if not intent_response:
        if is_likely_knowledge_query(user_input): # Check again if it's a knowledge query on Bedrock fail
            return handle_knowledge_base_intent(conversation_id, {}, user_input)
        add_message_to_history(conversation_id, "assistant", "I'm having trouble understanding. Could you try again?")
        return "I'm having trouble understanding. Could you try again?"
    
    try:
        parsed_intent = parse_intent_response(intent_response)
        logger.info(f"Parsed intent: {json.dumps(parsed_intent)}")
    except Exception: # Catch generic exception from parse_intent_response
        if is_likely_knowledge_query(user_input): # Fallback for parsing error
            return handle_knowledge_base_intent(conversation_id, {}, user_input)
        add_message_to_history(conversation_id, "assistant", "I'm having trouble processing your request. Could you try asking in a different way?")
        return "I'm having trouble processing your request. Could you try asking in a different way?"
    
    intent_type = parsed_intent.get('intent_type')
    confidence = parsed_intent.get('confidence', 0)
    entities = parsed_intent.get('entities', {})
    required_info = parsed_intent.get('required_info', [])
    
    if not intent_type or intent_type not in AGENT_CAPABILITIES:
        if is_likely_knowledge_query(user_input): # Fallback for unknown intent
            return handle_knowledge_base_intent(conversation_id, {}, user_input)
        add_message_to_history(conversation_id, "assistant", "I'm not sure what you're asking for. Could you please clarify?")
        return "I'm not sure what you're asking for. Could you please clarify?"
    
    capability = AGENT_CAPABILITIES[intent_type]
    if confidence < capability.get('confidence_threshold', 0.7):
        # If confidence is low, but it's a knowledge_base type or seems like one, try it.
        if intent_type == "knowledge_base" or is_likely_knowledge_query(user_input):
            return handle_knowledge_base_intent(conversation_id, entities, user_input)
        
        clarification_msg = f"I think you might be asking about {intent_type.replace('_', ' ')}, but I'm not entirely sure. Could you provide more details?"
        add_message_to_history(conversation_id, "assistant", clarification_msg)
        return clarification_msg
    
    if required_info:
        collected_info = {k: v for k, v in entities.items() if v} # Ensure only non-empty entities are collected
        update_conversation_state(conversation_id, {
            'state': 'collecting_info',
            'pending_intent': intent_type,
            'collected_info': collected_info,
            'required_info': required_info
        })
        next_info = required_info[0]
        prompt_msg = f"I can help with your {intent_type.replace('_', ' ')}. I just need a few more details. Could you please provide your {next_info.replace('_', ' ')}?"
        add_message_to_history(conversation_id, "assistant", prompt_msg)
        return prompt_msg
    
    return process_intent(conversation_id, intent_type, entities, user_input)

def format_response(success, message, status_code=200):
    """Formats the Lambda response."""
    return {
        'statusCode': status_code,
        'body': json.dumps({
            'success': success,
            'message': message
        }),
        'headers': {
            'Content-Type': 'application/json'
        }
    }
