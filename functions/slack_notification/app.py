import json
import logging
import os
import textwrap
import boto3
import botocore
from urllib.request import HTTPError, Request, URLError, urlopen
import re

# Setting up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def is_valid_instance_id(instance_id):
    pattern = r'^i-[a-z0-9]{8,17}$'
    
    if re.match(pattern, instance_id):
        return True
    else:
        return False

def is_valid_automation_execution_id(automation_execution_id):
    pattern = r'^[a-z0-9-]+$'
    
    if re.match(pattern, automation_execution_id):
        return True
    else:
        return False

# https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets_lambda.html
def get_slack_web_hook_url(secretSlackWebHookUrlName):
    method = 'GET'
    request_headers = {"X-Aws-Parameters-Secrets-Token": os.environ.get('AWS_SESSION_TOKEN')}
    secrets_extension_http_port = "2773"
    url = "http://localhost:" + \
      secrets_extension_http_port + \
      "/secretsmanager/get?secretId=" + \
      secretSlackWebHookUrlName
      
    req = Request(
        url=url, 
        method=method,
        headers=request_headers 
    )

    try:
      response = urlopen(req)
      response_body = response.read().decode("utf-8")
      slack_web_hook_url = json.loads(response_body)["SecretString"]
      return slack_web_hook_url
    except HTTPError as e:
      logger.error('Request failed : %d %s', e.code, e.reason)
      raise e
    except URLError as e:
      logger.error('Server connection failed: %s', e.reason)
      raise e

def create_slack_main(instanceId, automationExecutionId):
    return textwrap.dedent('''
      [AWS SAW auto notification]
      Your instance {instanceId} may not be associated SSM managed node.
      Please check SAW result in the slack thread or check SSM automation executionId {executionId}.
    ''').format(instanceId=instanceId, executionId=automationExecutionId).strip()

def create_slack_thread(outputs):
    return textwrap.dedent('''
      AWS SAW result
      ===
      {outputs}
      ===
    ''').format(outputs=outputs).strip()


def send_slack_message(slackWebHookUrl, main, thread):
    
    data = {
        "main": main,
        "thread": thread
    }

    method = 'POST'
    request_headers = { 'Content-Type': 'application/json; charset=utf-8' }
    body = json.dumps(data).encode("utf-8")
    
    req = Request(
        url=slackWebHookUrl, 
        data=body, 
        method=method,
        headers=request_headers 
    )
    
    try:
      response = urlopen(req)
      response.read()
      logger.info('Slack Message posted')
    except HTTPError as e:
      logger.error('Request failed : %d %s', e.code, e.reason)
      raise e
    except URLError as e:
      logger.error('Server connection failed: %s', e.reason)
      raise e

def create_sns_subject(instanceId):
    return "[AWS SAW auto notification]Instance \"" + instanceId + "\" may not be associated SSM managed node"

def create_sns_message(instanceId, outputs, automationExecutionId):
    return textwrap.dedent('''
      Your instance {instanceId} may not be associated SSM managed node.
      Please check below SAW result or check SSM automation executionId {executionId}.
      ===
      {outputs}
      ===
      Thanks.
    ''').format(instanceId=instanceId, executionId=automationExecutionId, outputs=outputs).strip()

def send_sns_message(topicArn, subject, message):
    
    sns_client = boto3.client('sns')
    req = {
        'TopicArn': topicArn,
        'Message': message,
        'Subject': subject
    }
    
    try:
        sns_response = sns_client.publish(**req)
        logger.info('SNS message posted')
    except botocore.exceptions.ClientError as e:
       logger.error("Client error : %s", e)
       raise e

def lambda_handler(event, context):

    # Check required environment
    secretSlackWebHookUrlName = os.environ.get('SECRET_SLACK_WEB_HOOK_URL_NAME')
    topicArn = os.environ.get('TOPIC_ARN')
    
    enableSlackWebHookUrl = secretSlackWebHookUrlName is not None and secretSlackWebHookUrlName.strip()
    enableTopicArn = topicArn is not None and topicArn.strip()

    if not enableSlackWebHookUrl and not enableTopicArn:
       raise "Env SLACK_WEB_HOOK_URL and TOPIC_ARN are not set.Please set SLACK_WEB_HOOK_URL or TOPIC_ARN, or both"
    
    # Parse SAW result from Step Functions
    try:
       automationExecutionId = event['Payload']['DescribeResult']['AutomationExecutionMetadataList'][0]['AutomationExecutionId']
       logging.info('automationExecutionId = %s', automationExecutionId)
       if not is_valid_automation_execution_id(automationExecutionId):
          raise "automationExecutionId is not valid"

       outputs = event['Payload']['DescribeResult']['AutomationExecutionMetadataList'][0]['Outputs']['FinalOutput.Message'][0]

       instanceId = event['Payload']['ExecutionInput']['detail']['instance-id']
       logging.info('instanceId = %s', instanceId)
       if not is_valid_instance_id(instanceId):
          raise "instanceId is not valid"

    except KeyError:
       raise "KeyError occur during event parse"
     
    # Send message to slack
    if enableSlackWebHookUrl:
      slackWebHookUrl = get_slack_web_hook_url(secretSlackWebHookUrlName)
      if slackWebHookUrl.startswith('https://'):
        send_slack_message(slackWebHookUrl, create_slack_main(instanceId, automationExecutionId), create_slack_thread(outputs))
      else:
         raise "Slack web hook url must be used HTTPS. Please check your slack web hook url"
    # Send SNS message
    if enableTopicArn:
       send_sns_message(topicArn, create_sns_subject(instanceId), create_sns_message(instanceId, outputs, automationExecutionId))
       