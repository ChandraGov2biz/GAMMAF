"""
Intent Handler Lambda for Lia AI Agent

This Lambda function connects to Amazon Bedrock, uses Claude 3.5 Haiku to:
1. Identify user intent from input text
2. Route to appropriate service (Knowledge Base, Govcraft CRM, etc.)
3. Track conversation state for multi-turn interactions
4. Return response text to be used by the Twilio handler

Date: May 2025
"""

import json
import os
import boto3
import uuid
import time
import logging
import requests
from datetime import datetime
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ------------------------
# In-memory configuration for POC (will be moved to DynamoDB)
# ------------------------

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
        "inference_profile_arn": "arn:aws:bedrock:us-east-2:203918860835:inference-profile/us.anthropic.claude-3-5-haiku-20241022-v1:0"
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

# Conversation state would be in DynamoDB, using in-memory for POC
active_conversations = {}

# ------------------------
# Amazon Bedrock Configuration
# ------------------------

# Bedrock model parameters
BEDROCK_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"  # Claude 3 Haiku version that's widely available
BEDROCK_REGION = "us-east-2"  # Update to your Bedrock region

# Connect to Amazon Bedrock
try:
    bedrock_runtime = boto3.client(
        service_name="bedrock-runtime",
        region_name=BEDROCK_REGION
    )
    
    # Also create Bedrock Agent Runtime client for knowledge base access
    bedrock_agent_runtime = boto3.client(
        service_name="bedrock-agent-runtime",
        region_name=BEDROCK_REGION
    )
    
    logger.info("Successfully connected to Amazon Bedrock services")
except Exception as e:
    logger.error(f"Error connecting to Amazon Bedrock: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())
    bedrock_runtime = None
    bedrock_agent_runtime = None

# ------------------------
# Main Lambda Handler
# ------------------------

def lambda_handler(event, context):
    """
    Main handler for the Intent Recognition Lambda.
    
    Expected event structure:
    {
        "text": "User's input text",
        "conversation_id": "optional-existing-conversation-id",
        "user_id": "identifier-for-the-user", 
        "channel": "SMS" or "Voice",
        "additional_context": {} // Optional additional context
    }
    """
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Extract parameters from the event
        user_input = event.get('text', '')
        conversation_id = event.get('conversation_id')
        user_id = event.get('user_id', 'unknown_user')
        channel = event.get('channel', 'unknown')
        additional_context = event.get('additional_context', {})
        
        # Validate input
        if not user_input:
            return format_response(False, "Missing required parameter: text", 400)
        
        # Get or create conversation state
        conversation_state = get_conversation_state(conversation_id, user_id, channel)
        conversation_id = conversation_state['conversation_id']
        
        # Add the user's message to the conversation history
        add_message_to_history(conversation_id, "user", user_input)
        
        # Get the full conversation history (for context)
        conversation_history = get_conversation_history(conversation_id)
        
        # For common knowledge queries, skip intent recognition and go straight to knowledge base
        # This optimization helps with simple informational queries like "San Antonio City Hall hours"
        if is_likely_knowledge_query(user_input):
            logger.info(f"Query '{user_input}' identified as likely knowledge query, bypassing intent recognition")
            return format_response(True, handle_knowledge_base_intent(conversation_id, {}, user_input))
        
        # Determine if we're in a multi-turn interaction
        current_state = conversation_state.get('state', 'initial')
        pending_intent = conversation_state.get('pending_intent')
        
        # Process based on current state
        if current_state != 'initial' and pending_intent:
            # We're in the middle of a multi-turn interaction
            response = continue_conversation(
                conversation_id, 
                user_input, 
                current_state, 
                pending_intent, 
                conversation_history
            )
        else:
            # New interaction - identify intent
            response = identify_and_process_intent(
                conversation_id, 
                user_input, 
                conversation_history,
                additional_context
            )
        
        # Return the response
        return format_response(True, response)
        
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return format_response(False, f"Internal server error: {str(e)}", 500)

def is_likely_knowledge_query(text):
    """
    Quick heuristic to identify if a query is likely a simple knowledge question.
    This helps optimize the flow for common information requests.
    """
    text = text.lower()
    
    # Location/hour related queries are very likely knowledge-based
    location_terms = ['where', 'location', 'address', 'directions', 'map']
    time_terms = ['hour', 'time', 'when', 'open', 'close', 'schedule']
    info_terms = ['how to', 'information', 'details', 'guide', 'instruction']
    
    # Check if query contains any of these patterns
    if any(term in text for term in location_terms + time_terms + info_terms):
        return True
        
    # Check if query is short (likely a simple question) and ends with a question mark
    if len(text.split()) < 8 and '?' in text:
        return True
        
    return False

# ------------------------
# Conversation State Management
# ------------------------

def get_conversation_state(conversation_id, user_id, channel):
    """
    Gets or creates a conversation state.
    In a production environment, this would use DynamoDB.
    """
    global active_conversations
    
    # If conversation ID is provided and exists, return it
    if conversation_id and conversation_id in active_conversations:
        # Update last activity time
        active_conversations[conversation_id]['last_activity'] = int(time.time())
        return active_conversations[conversation_id]
    
    # Otherwise, create a new conversation
    new_conversation_id = conversation_id or str(uuid.uuid4())
    timestamp = int(time.time())
    
    # Create new conversation state
    conversation_state = {
        'conversation_id': new_conversation_id,
        'user_id': user_id,
        'channel': channel,
        'start_time': timestamp,
        'last_activity': timestamp,
        'state': 'initial',
        'pending_intent': None,
        'collected_info': {},
        'message_history': []
    }
    
    # Store in memory (would be DynamoDB in production)
    active_conversations[new_conversation_id] = conversation_state
    logger.info(f"Created new conversation: {new_conversation_id}")
    
    return conversation_state

def add_message_to_history(conversation_id, role, message):
    """
    Adds a message to the conversation history.
    """
    if conversation_id not in active_conversations:
        logger.warning(f"Conversation {conversation_id} not found")
        return
    
    timestamp = int(time.time())
    
    # Add message to history
    active_conversations[conversation_id]['message_history'].append({
        'role': role,
        'content': message,
        'timestamp': timestamp
    })
    
    # Update last activity timestamp
    active_conversations[conversation_id]['last_activity'] = timestamp

def get_conversation_history(conversation_id, max_messages=10):
    """
    Gets the conversation history for a given conversation.
    Limited to last 'max_messages' for context window management.
    """
    if conversation_id not in active_conversations:
        logger.warning(f"Conversation {conversation_id} not found")
        return []
    
    # Get message history, limited to last 'max_messages'
    history = active_conversations[conversation_id]['message_history']
    return history[-max_messages:] if history else []

def update_conversation_state(conversation_id, state_updates):
    """
    Updates the conversation state with new values.
    """
    if conversation_id not in active_conversations:
        logger.warning(f"Conversation {conversation_id} not found")
        return
    
    # Update the specified fields
    for key, value in state_updates.items():
        active_conversations[conversation_id][key] = value
    
    # Always update the last activity timestamp
    active_conversations[conversation_id]['last_activity'] = int(time.time())

# ------------------------
# Intent Identification and Processing
# ------------------------

def identify_and_process_intent(conversation_id, user_input, conversation_history, additional_context=None):
    """
    Uses Amazon Bedrock to identify the user's intent and processes it accordingly.
    """
    # Get capabilities for prompt context
    capabilities_context = format_capabilities_for_prompt()
    
    # Format conversation history for the prompt
    conversation_context = format_conversation_history(conversation_history)
    
    # Create the prompt for Bedrock
    messages = create_intent_recognition_prompt(
        user_input, 
        capabilities_context, 
        conversation_context,
        additional_context
    )
    
    # Call Bedrock to identify intent
    intent_response = call_bedrock_model(messages)
    
    if not intent_response:
        # If Bedrock call failed, try direct knowledge base intent for simple queries
        if is_likely_knowledge_query(user_input):
            logger.info("Bedrock call failed but query looks like a knowledge query, trying knowledge base directly")
            return handle_knowledge_base_intent(conversation_id, {}, user_input)
            
        # Otherwise provide a fallback response
        add_message_to_history(conversation_id, "assistant", "I'm having trouble understanding. Could you please try again?")
        return "I'm having trouble understanding. Could you please try again?"
    
    # Parse the intent from the response
    try:
        parsed_intent = parse_intent_response(intent_response)
        logger.info(f"Parsed intent: {json.dumps(parsed_intent)}")
    except Exception as e:
        logger.error(f"Error parsing intent response: {str(e)}")
        logger.error(f"Raw intent response: {intent_response[:1000]}")  # Log first 1000 chars
        
        # If parsing fails but query looks like knowledge query, try knowledge base
        if is_likely_knowledge_query(user_input):
            logger.info("Intent parsing failed but query looks like a knowledge query, trying knowledge base directly")
            return handle_knowledge_base_intent(conversation_id, {}, user_input)
        
        add_message_to_history(conversation_id, "assistant", "I'm having trouble processing your request. Could you try asking in a different way?")
        return "I'm having trouble processing your request. Could you try asking in a different way?"
    
    # Process the identified intent
    intent_type = parsed_intent.get('intent_type')
    confidence = parsed_intent.get('confidence', 0)
    entities = parsed_intent.get('entities', {})
    required_info = parsed_intent.get('required_info', [])
    
    # Check if we have a valid intent with sufficient confidence
    if not intent_type or intent_type not in AGENT_CAPABILITIES:
        # If no intent identified but query looks like knowledge query, try knowledge base
        if is_likely_knowledge_query(user_input):
            logger.info("No intent identified but query looks like a knowledge query, trying knowledge base directly")
            return handle_knowledge_base_intent(conversation_id, {}, user_input)
            
        add_message_to_history(conversation_id, "assistant", "I'm not sure what you're asking for. Could you please clarify?")
        return "I'm not sure what you're asking for. Could you please clarify?"
    
    # Get capability configuration for this intent
    capability = AGENT_CAPABILITIES[intent_type]
    
    # Check confidence threshold
    if confidence < capability.get('confidence_threshold', 0.7):
        # For low confidence on what might be knowledge queries, try knowledge base anyway
        if intent_type == "knowledge_base" or is_likely_knowledge_query(user_input):
            logger.info(f"Low confidence ({confidence}) but trying knowledge base anyway")
            return handle_knowledge_base_intent(conversation_id, entities, user_input)
        
        # Low confidence - ask for clarification
        clarification_msg = f"I think you might be asking about {intent_type.replace('_', ' ')}, but I'm not entirely sure. Could you provide more details?"
        add_message_to_history(conversation_id, "assistant", clarification_msg)
        return clarification_msg
    
    # Check if we need more information to complete this intent
    if required_info:
        # Update conversation state to pending and save what we know so far
        collected_info = {}
        for entity, value in entities.items():
            if value:  # Only save non-empty values
                collected_info[entity] = value
        
        update_conversation_state(conversation_id, {
            'state': 'collecting_info',
            'pending_intent': intent_type,
            'collected_info': collected_info,
            'required_info': required_info
        })
        
        # Ask for the first missing piece of information
        next_info = required_info[0]
        prompt_msg = f"I can help with your {intent_type.replace('_', ' ')}. I just need a few more details. Could you please provide your {next_info.replace('_', ' ')}?"
        add_message_to_history(conversation_id, "assistant", prompt_msg)
        return prompt_msg
    
    # If we have all required info, process the intent
    return process_intent(conversation_id, intent_type, entities, user_input)

def format_capabilities_for_prompt():
    """
    Formats the agent capabilities for inclusion in the prompt.
    """
    capability_descriptions = []
    
    for intent_name, config in AGENT_CAPABILITIES.items():
        description = config.get('description', 'No description available')
        required_params = config.get('required_params', [])
        
        formatted_intent = (
            f"Intent: {intent_name}\n"
            f"Description: {description}\n"
        )
        
        if required_params:
            formatted_intent += f"Required information: {', '.join(required_params)}\n"
            
        capability_descriptions.append(formatted_intent)
    
    return "\n".join(capability_descriptions)

def format_conversation_history(conversation_history):
    """
    Formats the conversation history for inclusion in the prompt.
    """
    if not conversation_history:
        return "No previous conversation."
    
    formatted_history = []
    
    for message in conversation_history:
        role = "User" if message['role'] == 'user' else "Assistant"
        content = message['content']
        formatted_history.append(f"{role}: {content}")
    
    return "\n".join(formatted_history)

def create_intent_recognition_prompt(user_input, capabilities_context, conversation_context, additional_context=None):
    """
    Creates a prompt for the Bedrock model to identify the user's intent.
    """
    # Human message - the user's input and context
    human_message = (
        f"Please analyze the following user input from a conversation with an AI assistant:\n\n"
        f"USER INPUT: {user_input}\n\n"
        f"CONVERSATION HISTORY:\n{conversation_context}\n\n"
    )
    
    if additional_context:
        human_message += f"ADDITIONAL CONTEXT:\n{json.dumps(additional_context)}\n\n"
    
    human_message += (
        f"AVAILABLE CAPABILITIES:\n{capabilities_context}\n\n"
        f"Please identify the most likely intent of the user and extract any relevant entities. "
        f"Also identify any information that is still required to fulfill this intent."
        f"Respond in the following JSON format:\n"
        f"```json\n"
        f"{{\n"
        f'  "intent_type": "one of the intents listed above or null if none match",\n'
        f'  "confidence": "a float between 0 and 1 indicating confidence in this intent",\n'
        f'  "entities": {{\n'
        f'    "entity_name": "extracted value",\n'
        f'    ...\n'
        f'  }},\n'
        f'  "required_info": ["list", "of", "missing", "required", "information"],\n'
        f'  "reasoning": "brief explanation of why this intent was selected"\n'
        f"}}\n"
        f"```\n"
        f"Important: For general questions about agency services, hours, locations, or policies, use the knowledge_base intent."
    )
    
    # Format as messages for the updated Bedrock API
    return [
        {"role": "human", "content": human_message}
    ]

def call_bedrock_model(messages):
    """
    Calls the Bedrock model with the given messages.
    """
    if not bedrock_runtime:
        logger.error("Bedrock client not available")
        return None
    
    try:
        # Log the request for debugging
        logger.info(f"Calling Bedrock model {BEDROCK_MODEL_ID} with first 200 chars of message: {messages[0].get('content', '')[:200]}...")
        
        # Format the request for the Anthropic Claude model
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1024,
            "messages": messages,
            "temperature": 0.1  # Low temperature for more deterministic responses
        }
        
        # Call the Bedrock Runtime invoke_model API
        response = bedrock_runtime.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(request_body)
        )
        
        # Parse and return the response
        response_body = json.loads(response.get('body').read())
        
        # Log first 200 chars of response for debugging
        if response_body and 'content' in response_body and len(response_body['content']) > 0:
            logger.info(f"Bedrock response received: {response_body['content'][0].get('text', '')[:200]}...")
        else:
            logger.warning(f"Unexpected Bedrock response structure: {json.dumps(response_body)[:200]}...")
        
        # Return the text content from the response
        if response_body and 'content' in response_body and len(response_body['content']) > 0:
            return response_body['content'][0].get('text', '')
        else:
            logger.error(f"Missing expected content in Bedrock response: {json.dumps(response_body)[:500]}")
            return None
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'Unknown error')
        logger.error(f"Bedrock ClientError: {error_code} - {error_message}")
        return None
    except Exception as e:
        logger.error(f"Error calling Bedrock model: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def parse_intent_response(response_text):
    """
    Parses the JSON response from the Bedrock model.
    """
    # Find JSON code block in the response
    json_start = response_text.find('```json')
    json_end = response_text.find('```', json_start + 6)
    
    if json_start == -1 or json_end == -1:
        # No JSON block found, try to find raw JSON
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1
        
        if json_start == -1 or json_end == 0:
            raise ValueError("Could not find JSON in response")
            
        json_str = response_text[json_start:json_end]
    else:
        # Extract JSON from code block
        json_str = response_text[json_start + 7:json_end].strip()
    
    # Parse JSON
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON: {json_str}")
        raise ValueError("Invalid JSON in response")

def continue_conversation(conversation_id, user_input, current_state, pending_intent, conversation_history):
    """
    Continues a multi-turn conversation to collect required information.
    """
    # Get the current conversation state
    conversation = active_conversations.get(conversation_id)
    if not conversation:
        logger.warning(f"Conversation {conversation_id} not found")
        return "I'm sorry, but I've lost track of our conversation. Could we start again?"
    
    # Get collected and required information
    collected_info = conversation.get('collected_info', {})
    required_info = conversation.get('required_info', [])
    
    if not required_info:
        # No more information needed, process the intent
        update_conversation_state(conversation_id, {
            'state': 'initial',
            'pending_intent': None
        })
        return process_intent(conversation_id, pending_intent, collected_info, user_input)
    
    # We need more information - use Bedrock to extract the current info
    current_field = required_info[0]
    
    # Create prompt to extract information
    prompt = [
        {"role": "human", "content": f"I need to extract the value for '{current_field}' from this user message: '{user_input}'. If the information is provided, return it as a simple text string. If not, respond with 'NOT_PROVIDED'."}
    ]
    
    # Call Bedrock to extract information
    extraction_response = call_bedrock_model(prompt)
    
    if not extraction_response or extraction_response.strip() == "NOT_PROVIDED":
        # Information not provided, ask again
        prompt_msg = f"I still need your {current_field.replace('_', ' ')} to continue. Could you please provide it?"
        add_message_to_history(conversation_id, "assistant", prompt_msg)
        return prompt_msg
    
    # Add the extracted information to collected_info
    extracted_value = extraction_response.strip()
    if extracted_value.lower() in ["not provided", "not_provided", "none", "null", ""]:
        # Information not provided, ask again
        prompt_msg = f"I couldn't understand your {current_field.replace('_', ' ')}. Could you please provide it clearly?"
        add_message_to_history(conversation_id, "assistant", prompt_msg)
        return prompt_msg
    
    # Update collected information
    collected_info[current_field] = extracted_value
    
    # Remove this field from required_info
    required_info.pop(0)
    
    # Update conversation state
    update_conversation_state(conversation_id, {
        'collected_info': collected_info,
        'required_info': required_info
    })
    
    # Check if we need more information
    if required_info:
        # Ask for the next piece of information
        next_field = required_info[0]
        prompt_msg = f"Thanks for providing your {current_field.replace('_', ' ')}. Now, could you please provide your {next_field.replace('_', ' ')}?"
        add_message_to_history(conversation_id, "assistant", prompt_msg)
        return prompt_msg
    
    # All information collected, process the intent
    update_conversation_state(conversation_id, {
        'state': 'initial',
        'pending_intent': None
    })
    
    # Process the intent with all collected information
    return process_intent(conversation_id, pending_intent, collected_info, user_input)

def process_intent(conversation_id, intent_type, entities, original_input):
    """
    Processes an identified intent with the collected entities.
    """
    # Get capability configuration
    capability = AGENT_CAPABILITIES.get(intent_type)
    if not capability:
        logger.error(f"Unknown intent type: {intent_type}")
        error_msg = "I'm sorry, but I don't know how to handle that request."
        add_message_to_history(conversation_id, "assistant", error_msg)
        return error_msg
    
    logger.info(f"Processing intent: {intent_type} with entities: {json.dumps(entities)}")
    
    # Check for simple response template
    if 'response_template' in capability:
        response = capability['response_template']
        add_message_to_history(conversation_id, "assistant", response)
        return response
    
    # Otherwise, route to the appropriate handler
    if intent_type == 'knowledge_base':
        return handle_knowledge_base_intent(conversation_id, entities, original_input)
    elif intent_type == 'payment_inquiry':
        return handle_payment_inquiry_intent(conversation_id, entities)
    elif intent_type == 'appointment_scheduling':
        return handle_appointment_scheduling_intent(conversation_id, entities)
    else:
        # Fallback - use Bedrock to generate a response
        return generate_generic_response(conversation_id, intent_type, entities, original_input)

# ------------------------
# Intent Handlers
# ------------------------

def handle_knowledge_base_intent(conversation_id, entities, original_input):
    """
    Handles knowledge base inquiries by calling the knowledge base API.
    First tries Bedrock Agent Runtime RetrieveAndGenerate API, falls back to API endpoint.
    """
    logger.info(f"Handling knowledge base intent for query: {original_input}")
    
    try:
        # Get knowledge base configuration from capabilities
        knowledge_base_id = AGENT_CAPABILITIES.get('knowledge_base', {}).get('knowledge_base_id')
        inference_profile_arn = AGENT_CAPABILITIES.get('knowledge_base', {}).get('inference_profile_arn')
        
        if not knowledge_base_id or not inference_profile_arn or not bedrock_agent_runtime:
            logger.warning("Missing knowledge base configuration or Bedrock Agent Runtime client")
            # Try the API endpoint as fallback
            return handle_knowledge_base_api_fallback(conversation_id, original_input)
        
        # Log the configuration
        logger.info(f"Using Knowledge Base ID: {knowledge_base_id}")
        logger.info(f"Using Inference Profile ARN: {inference_profile_arn}")
        
        # Try using Retrieve and Generate with Inference Profile directly
        try:
            response = bedrock_agent_runtime.retrieve_and_generate(
                input={'text': original_input},
                retrieveAndGenerateConfiguration={
                    'type': 'KNOWLEDGE_BASE',
                    'knowledgeBaseConfiguration': {
                        'knowledgeBaseId': knowledge_base_id,
                        'modelArn': inference_profile_arn,
                        'retrievalConfiguration': {
                            'vectorSearchConfiguration': {
                                'numberOfResults': 5  # Number of relevant documents to retrieve
                            }
                        }
                    }
                }
            )
            
            logger.info("Bedrock Agent Runtime retrieve_and_generate called successfully")
            
            # Extract answer from response
            answer = response.get('output', {}).get('text', 'I couldn\'t find information on that topic.')
            
            # Extract citations if available
            citations = []
            if 'citations' in response.get('output', {}):
                citations = response['output']['citations']
                logger.info(f"Retrieved {len(citations)} citations")
                
                # Add citation info to response if available
                if citations:
                    citation_info = "\n\nSources:"
                    for i, citation in enumerate(citations[:3]):  # Show top 3 sources
                        source_name = citation.get('retrievedReferences', [{}])[0].get('location', {}).get('s3Location', {}).get('uri', 'Unknown source')
                        source_name = source_name.split('/')[-1]  # Just the filename
                        citation_info += f"\n- {source_name}"
                    answer += citation_info
            
            # Add response to conversation history
            add_message_to_history(conversation_id, "assistant", answer)
            return answer
                
        except Exception as e:
            logger.error(f"Error using Bedrock Agent Runtime for knowledge base: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            # Fall back to API endpoint
            return handle_knowledge_base_api_fallback(conversation_id, original_input)
            
    except Exception as e:
        logger.error(f"Unexpected error in handle_knowledge_base_intent: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        # Fall back to API endpoint
        return handle_knowledge_base_api_fallback(conversation_id, original_input)

def handle_knowledge_base_api_fallback(conversation_id, original_input):
    """
    Falls back to the knowledge base API endpoint if direct Bedrock Agent Runtime fails.
    """
    # Get API endpoint from capabilities
    endpoint = AGENT_CAPABILITIES.get('knowledge_base', {}).get('endpoint')
    if not endpoint:
        error_msg = "I'm sorry, but I can't access our knowledge base at the moment."
        add_message_to_history(conversation_id, "assistant", error_msg)
        return error_msg
    
    try:
        logger.info(f"Falling back to knowledge base API endpoint: {endpoint}")
        
        # Prepare request to knowledge base API
        payload = {
            "query": original_input
        }
        
        # Call API
        response = requests.post(endpoint, json=payload)
        
        # Check for successful response
        if response.status_code == 200:
            # Parse response
            resp_data = response.json()
            logger.info(f"Knowledge base API response: {json.dumps(resp_data)[:500]}...")
            
            answer = resp_data.get('answer', "I couldn't find information on that topic.")
            
            # Add response to conversation history
            add_message_to_history(conversation_id, "assistant", answer)
            return answer
        else:
            logger.error(f"Knowledge base API error: {response.status_code} - {response.text}")
            error_msg = "I'm sorry, but I'm having trouble retrieving that information right now."
            add_message_to_history(conversation_id, "assistant", error_msg)
            return error_msg
            
    except Exception as e:
        logger.error(f"Error calling knowledge base API: {str(e)}")
        error_msg = "I'm sorry, but I'm having trouble accessing our knowledge base at the moment."
        add_message_to_history(conversation_id, "assistant", error_msg)
        return error_msg

def handle_payment_inquiry_intent(conversation_id, entities):
    """
    Handles payment inquiries by calling the Govcraft API.
    Note: This is a stub implementation until Govcraft API details are provided.
    """
    logger.info("Handling payment inquiry intent with entities: " + json.dumps(entities))
    
    # Check if we have the required entities
    account_number = entities.get('account_number')
    
    if not account_number:
        error_msg = "I need your account number to check payment information. Could you please provide it?"
        add_message_to_history(conversation_id, "assistant", error_msg)
        return error_msg
    
    # TODO: Replace with actual Govcraft API call when details are provided
    # For now, return a placeholder response
    response = (
        f"I found your account {account_number}. Your current balance is $245.00, "
        f"with a payment of $45.00 due on May 25, 2025. Would you like to make a payment now?"
    )
    
    add_message_to_history(conversation_id, "assistant", response)
    return response

def handle_appointment_scheduling_intent(conversation_id, entities):
    """
    Handles appointment scheduling by calling the appointment API.
    Note: This is a stub implementation until appointment API details are provided.
    """
    logger.info("Handling appointment scheduling intent with entities: " + json.dumps(entities))
    
    # Check if we have the required entities
    date = entities.get('date')
    time = entities.get('time')
    purpose = entities.get('purpose')
    
    if not date or not time:
        missing = []
        if not date: missing.append("date")
        if not time: missing.append("time")
        
        error_msg = f"I need to know what {' and '.join(missing)} you'd prefer for your appointment. Could you please provide that?"
        add_message_to_history(conversation_id, "assistant", error_msg)
        return error_msg
    
    # TODO: Replace with actual appointment API call when details are provided
    # For now, return a placeholder response
    response = (
        f"I've scheduled your appointment for {date} at {time}"
        + (f" for {purpose}" if purpose else "") + 
        ". You'll receive a confirmation message shortly. Is there anything else you need help with?"
    )
    
    add_message_to_history(conversation_id, "assistant", response)
    return response

def generate_generic_response(conversation_id, intent_type, entities, original_input):
    """
    Generates a generic response for intents without specific handlers.
    Uses Bedrock to create a natural language response.
    """
    # Create a prompt for Bedrock
    prompt = [
        {"role": "human", "content": f"I need a response for a user who has a {intent_type.replace('_', ' ')} request: '{original_input}'. The response should be helpful, concise, and friendly."}
    ]
    
    # Call Bedrock to generate response
    response = call_bedrock_model(prompt)
    
    if not response:
        # Fallback response if Bedrock call fails
        response = f"I understand you're asking about {intent_type.replace('_', ' ')}. How can I help you with that specifically?"
    
    add_message_to_history(conversation_id, "assistant", response)
    return response

# ------------------------
# Helper Functions
# ------------------------

def format_response(success, message, status_code=200):
    """
    Formats the Lambda response.
    """
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
