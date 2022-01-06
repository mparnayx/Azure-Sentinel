import requests
import datetime
import dateutil
import logging
import boto3
import gzip
import io
import csv
import time
import os
import sys
import json
import hashlib
import hmac
import base64
import re
from threading import Thread
from io import StringIO
import platform

import azure.functions as func

sentinel_customer_id = os.environ.get('WorkspaceID')
sentinel_shared_key = os.environ.get('WorkspaceKey')
aws_access_key_id = os.environ.get('AWSAccessKeyId')
aws_secret_acces_key = os.environ.get('AWSSecretAccessKey')
aws_s3_bucket = os.environ.get('S3Bucket')
aws_region_name = os.environ.get('AWSRegionName')
s3_folder = os.environ.get('S3Folder')
sentinel_log_type = os.environ.get('LogAnalyticsCustomLogName')
fresh_event_timestamp = os.environ.get('FreshEventTimeStamp')

logAnalyticsUri = os.environ.get('LAURI')

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):    
    logAnalyticsUri = 'https://' + sentinel_customer_id + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern,str(logAnalyticsUri))
if(not match):
    raise Exception("Invalid Log Analytics Uri.")

# Boolean Values
isCoreFieldsAllTable = os.environ.get('CoreFieldsAllTable')
isSplitAWSResourceTypes = os.environ.get('SplitAWSResourceTypes')

# TODO: Read Collection schedule from environment variable as CRON expression; This is also Azure Function Trigger Schedule
collection_schedule = int(fresh_event_timestamp)

def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError as e:
        return False
    return True

def split_teleport(message):
    is_between_quotes = False
    return_arr = []
    last_space_idx = -1
    for i in range(len(message)):
        char = message[i]
        if char == '"':
            is_between_quotes = not is_between_quotes
        if char == ' ' and not is_between_quotes:
            return_arr.append(message[last_space_idx+1:i])
            last_space_idx = i
    return return_arr

def split_s3(message):
    is_between_quotes = False
    is_between_brackets = False
    return_arr = []
    last_space_idx = -1
    for i in range(len(message)):
        char = message[i]
        if char == '"':
            is_between_quotes = not is_between_quotes
        if char == '[' and not is_between_brackets:
            is_between_brackets = True
        if char == ']' and is_between_brackets:
            is_between_brackets = False
        if char == ' ' and not is_between_quotes and not is_between_brackets:
            return_arr.append(message[last_space_idx+1:i])
            last_space_idx = i
    for i in range(len(return_arr)):
        if return_arr[i][0] == '"':
            return_arr[i] = return_arr[i].strip('"')
    return return_arr



def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    logging.info(platform.python_version())
    
    logging.info('Starting program')
    
    cli = S3Client(aws_access_key_id, aws_secret_acces_key, aws_region_name, aws_s3_bucket)
    ts_from, ts_to = cli.get_time_interval()
    print("From:{0}".format(ts_from))
    print("To:{0}".format(ts_to))

    logging.info('Searching files last modified from {} to {}'.format(ts_from, ts_to))
    obj_list = cli.get_files_list(ts_from, ts_to)

    failed_sent_events_number = 0
    successfull_sent_events_number = 0    
    coreEvents = [] 
    failedEvents = [] 
    file_events = 0
    t0 = time.time()    
    sentinel = AzureSentinelConnector(logAnalyticsUri, sentinel_customer_id, sentinel_shared_key, sentinel_log_type, queue_size=15000, bulks_number=10)
 

    for obj in obj_list:
        log_events = cli.process_obj(obj)       
        
        for log in log_events:
            if len(log) > 0:
                try:
                    json_object = json.loads(log)
                    if "id" in json_object:
                        # Parse different log types
                        
                        if json_object['metadata']['tags']['resource_type'] == 'vpc-log':
                            #vpc-log
                            message = json_object['message']
                            """ <version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>"""

                            msg_arr = message.split(' ')

                            json_object['message'] = {}

                            json_object['message']['cn1'] = msg_arr[0] if msg_arr[0] != '-' else ''
                            json_object['message']['cn1Label'] = 'The VPC Flow Logs version.'
                            json_object['message']['cs3'] = msg_arr[1] if msg_arr[1] != '-' else ''
                            json_object['message']['cs3Label'] = 'The AWS account ID of the owner of the source network interface for which traffic is recorded.'
                            json_object['message']['cs4'] = msg_arr[2] if msg_arr[2] != '-' else ''
                            json_object['message']['cs4Label'] = 'The ID of the network interface for which the traffic is recorded.'
                            json_object['message']['src'] = msg_arr[3] if msg_arr[3] != '-' else ''
                            json_object['message']['dst'] = msg_arr[4] if msg_arr[4] != '-' else ''
                            json_object['message']['spt'] = msg_arr[5] if msg_arr[5] != '-' else ''
                            json_object['message']['dpt'] = msg_arr[6] if msg_arr[6] != '-' else ''
                            json_object['message']['cn2'] = msg_arr[7] if msg_arr[7] != '-' else ''
                            json_object['message']['cn2Label'] = 'The IANA protocol number of the traffic.'
                            json_object['message']['cn3'] = msg_arr[8] if msg_arr[8] != '-' else ''
                            json_object['message']['cn3Label'] = 'The number of packets transferred during the flow.'
                            json_object['message']['in'] = msg_arr[9] if msg_arr[9] != '-' else ''
                            json_object['message']['cs1'] = msg_arr[10] if msg_arr[10] != '-' else ''
                            json_object['message']['cs1Label'] = 'The time, in Unix seconds, when the first packet of the flow was received within the aggregation interval.'
                            json_object['message']['cs2'] = msg_arr[11] if msg_arr[11] != '-' else ''
                            json_object['message']['cs2Label'] = 'The time, in Unix seconds, when the last packet of the flow was received within the aggregation interval.'
                            json_object['message']['act'] = msg_arr[12] if msg_arr[12] != '-' else ''
                            json_object['message']['log-status'] = msg_arr[13] if msg_arr[13] != '-' else ''

                            log = json.dumps(json_object)
                        elif json_object['metadata']['tags']['resource_type'] == 'cloudfront':
                            #cloudfront
                            message = json_object['message']
                            
                            msg_arr = message.split('\t')
                            
                            json_object['message'] = {}
                            
                            json_object['message']['date'] = msg_arr[0] if msg_arr[0] != '-' else ''
                            json_object['message']['time'] = msg_arr[1] if msg_arr[1] != '-' else ''
                            json_object['message']['cs1'] = msg_arr[2] if msg_arr[2] != '-' else ''
                            json_object['message']['cs1Label'] = 'The edge location that served the request.'
                            json_object['message']['out'] = msg_arr[3] if msg_arr[3] != '-' else ''
                            json_object['message']['src'] = msg_arr[4] if msg_arr[4] != '-' else ''
                            json_object['message']['requestMethod'] = msg_arr[5] if msg_arr[5] != '-' else ''
                            json_object['message']['cs2'] = msg_arr[6] if msg_arr[6] != '-' else ''
                            json_object['message']['cs2Label'] = 'The domain name of the CloudFront distribution.'
                            json_object['message']['filePath'] = msg_arr[7] if msg_arr[7] != '-' else ''
                            json_object['message']['cn1'] = msg_arr[8] if msg_arr[8] != '-' else ''
                            json_object['message']['cn1Label'] = "The HTTP status code of the server's response."
                            json_object['message']['requestContext'] = msg_arr[9] if msg_arr[9] != '-' else ''
                            json_object['message']['requestClientApplication'] = msg_arr[10] if msg_arr[10] != '-' else ''
                            json_object['message']['cs3'] = msg_arr[11] if msg_arr[11] != '-' else ''
                            json_object['message']['cs3Label'] = 'The query string portion of the request URL, if any.'
                            json_object['message']['requestCookies'] = msg_arr[12] if msg_arr[12] != '-' else ''
                            json_object['message']['act'] = msg_arr[13] if msg_arr[13] != '-' else ''
                            json_object['message']['cs4'] = msg_arr[14] if msg_arr[14] != '-' else ''
                            json_object['message']['cs4Label'] = 'An opaque string that uniquely identifies a request.'
                            json_object['message']['dhost'] = msg_arr[15] if msg_arr[15] != '-' else ''
                            json_object['message']['app'] = msg_arr[16] if msg_arr[16] != '-' else ''
                            json_object['message']['in'] = msg_arr[17] if msg_arr[17] != '-' else ''
                            json_object['message']['cn2'] = msg_arr[18] if msg_arr[18] != '-' else ''
                            json_object['message']['cn2Label'] =  "The number of seconds (to the thousandth of a second) from when the server receives the viewer's request to when the server writes the last byte of the response to the output queue, as measured on the server."
                            json_object['message']['cs5'] = msg_arr[19] if msg_arr[19] != '-' else ''
                            json_object['message']['cs5Label'] = 'x-forwarded-for'
                            json_object['message']['cs6'] = msg_arr[22] if msg_arr[22] != '-' else ''
                            json_object['message']['cs6Label'] = "How the server classified the response just before returning the response to the viewer."
                            json_object['message']['dpt'] = msg_arr[26] if msg_arr[26] != '-' else ''
                            json_object['message']['cn3'] = msg_arr[27] if msg_arr[27] != '-' else ''
                            json_object['message']['cn3Label'] = "The number of seconds between receiving the request and writing the first byte of the response, as measured on the server."
                            json_object['message']['flexString1'] = msg_arr[28] if msg_arr[28] != '-' else ''
                            json_object['message']['flexString1Label'] = "When the value of the x-edge-result-type field (cs6) is Error, this field contains the specific type of error."

                            log = json.dumps(json_object)

                        elif json_object['metadata']['tags']['resource_type'] == 'dns':
                            message = json_object['message']
                            if message[0] != '{':
                                msg_arr = message.split(' ')
                                json_object['message'] = {}
                                
                                json_object['message']['version'] = msg_arr[0] if msg_arr[0] != '-' else ''
                                json_object['message']['account-id'] = msg_arr[1] if msg_arr[1] != '-' else ''
                                json_object['message']['interface-id'] = msg_arr[2] if msg_arr[2] != '-' else ''
                                json_object['message']['srcaddr'] = msg_arr[3] if msg_arr[3] != '-' else ''
                                json_object['message']['dstaddr'] = msg_arr[4] if msg_arr[4] != '-' else ''
                                json_object['message']['srcport'] = msg_arr[5] if msg_arr[5] != '-' else ''
                                json_object['message']['dstport'] = msg_arr[6] if msg_arr[6] != '-' else ''
                                json_object['message']['protocol'] = msg_arr[7] if msg_arr[7] != '-' else ''
                                json_object['message']['packets'] = msg_arr[8] if msg_arr[8] != '-' else ''
                                json_object['message']['bytes'] = msg_arr[9] if msg_arr[9] != '-' else ''
                                json_object['message']['start'] = msg_arr[10] if msg_arr[10] != '-' else ''
                                json_object['message']['end'] = msg_arr[11] if msg_arr[11] != '-' else ''
                                json_object['message']['action'] = msg_arr[12] if msg_arr[12] != '-' else ''
                                json_object['message']['log-status'] = msg_arr[13] if msg_arr[13] != '-' else ''
                            else:
                                message_object = json.loads(message)
                                
                                json_object['message'] = {}
                                
                                json_object['message']['cs1'] = message_object['account_id'] if 'account_id' in message_object else ''
                                json_object['message']['cs1Label'] = 'The ID of the AWS account that created the VPC.'
                                json_object['message']['cs2'] = message_object['region'] if 'region' in message_object else ''
                                json_object['message']['cs2Label'] = 'The AWS Region that you created the VPC in.'
                                json_object['message']['cs3'] = message_object['vpc_id'] if 'vpc_id' in message_object else ''
                                json_object['message']['cs3Label'] = 'The date and time that the query was submitted in ISO 8601 format and Coordinated Universal Time (UTC).'
                                json_object['message']['deviceCustomDate1'] = message_object['query_timestamp'] if 'query_timestamp' in message_object else ''
                                json_object['message']['deviceCustomDate1Label'] = 'queryTimeStamp'
                                json_object['message']['Name'] = message_object['query_name'] if 'query_name' in message_object else ''
                                json_object['message']['QueryType'] = message_object['query_type'] if 'query_type' in message_object else ''
                                json_object['message']['cs4'] = message_object['rcode'] if 'rcode' in message_object else ''
                                json_object['message']['cs4Label'] = 'The DNS response code that Resolver returned in response to the DNS query.'
                                json_object['message']['IPAddresses'] = []
                                if 'answers' in message_object:
                                    for obj in message_object['answers']:
                                        json_object['message']['IPAddresses'].append(obj['Rdata'])
                                json_object['message']['ClientIP'] = message_object['srcaddr'] if 'srcaddr' in message_object else ''
                                json_object['message']['cs5'] = message_object['srcids']['instance'] if 'srcids' in message_object and 'instance' in message_object['srcids'] else ''

                            log = json.dumps(json_object)
                        

                        elif json_object['metadata']['tags']['resource_type'] == 'teleport_alb' or json_object['metadata']['tags']['resource_type'] == 'public-elb' or json_object['metadata']['tags']['resource_type'] == 'private-elb':

                            message = json_object['message']
                            
                            msg_arr = split_teleport(message)
                            
                            json_object['message'] = {}
                            
                            json_object['message']['app'] = msg_arr[0] if msg_arr[0] != '"-"' else ''
                            json_object['message']['deviceCustomDate1'] = msg_arr[1] if msg_arr[1] != '"-"' else ''
                            json_object['message']['deviceCustomDate1Label'] = 'The time when the load balancer generated a response to the client, in ISO 8601 format.'
                            json_object['message']['dvchost'] = msg_arr[2] if msg_arr[2] != '"-"' else ''
                            json_object['message']['src'] = msg_arr[3].split(':')[0] if msg_arr[3] != '"-"' and msg_arr[3] != '-' and ':' in msg_arr[3] else ''
                            json_object['message']['spt'] = msg_arr[3].split(':')[1] if msg_arr[3] != '"-"' and msg_arr[3] != '-' and ':' in msg_arr[3] else ''
                            json_object['message']['dst'] = msg_arr[4].split(':')[0] if msg_arr[4] != '"-"' and msg_arr[4] != '-' and ':' in msg_arr[4] else ''
                            json_object['message']['dpt'] = msg_arr[4].split(':')[1] if msg_arr[4] != '"-"' and msg_arr[4] != '-' and ':' in msg_arr[4] else ''
                            json_object['message']['cfp1'] = msg_arr[5] if msg_arr[5] != '"-"' else ''
                            json_object['message']['cfp1Label'] = 'The total time elapsed (in seconds, with millisecond precision) from the time the load balancer received the request until the time it sent the request to a target.'
                            json_object['message']['cfp2'] = msg_arr[6] if msg_arr[6] != '"-"' else ''
                            json_object['message']['cfp2Label'] = 'The total time elapsed (in seconds, with millisecond precision) from the time the load balancer sent the request to a target until the target started to send the response headers.'
                            json_object['message']['cfp3'] = msg_arr[7] if msg_arr[7] != '"-"' else ''
                            json_object['message']['cfp3Label'] = 'The total time elapsed (in seconds, with millisecond precision) from the time the load balancer received the response header from the target until it started to send the response to the client.'
                            json_object['message']['cn1'] = msg_arr[8] if msg_arr[8] != '"-"' else ''
                            json_object['message']['cn1Label'] = 'The status code of the response from the load balancer.'
                            json_object['message']['cn2'] = msg_arr[9] if msg_arr[9] != '"-"' else ''
                            json_object['message']['cn2Label'] = 'The status code of the response from the target.'
                            json_object['message']['in'] = msg_arr[10] if msg_arr[10] != '"-"' else ''
                            json_object['message']['out'] = msg_arr[11] if msg_arr[11] != '"-"' else ''
                            json_object['message']['requestMethod'] = msg_arr[12].strip('"').split(' ')[0] if msg_arr[12] != '"-"' else ''
                            json_object['message']['request'] = msg_arr[12].strip('"').split(' ')[1] if msg_arr[12] != '"-"' else ''
                            json_object['message']['requestClientApplication'] = msg_arr[13].strip('"') if msg_arr[13] != '"-"' else ''
                            json_object['message']['cs1'] = msg_arr[14] if msg_arr[14] != '"-"' else ''
                            json_object['message']['cs1Label'] = 'SSL_Cipher'
                            json_object['message']['cs2'] = msg_arr[15] if msg_arr[15] != '"-"' else ''
                            json_object['message']['cs2Label'] = 'ssl_Protocol'
                            json_object['message']['cs3'] = msg_arr[16] if msg_arr[16] != '"-"' else ''
                            json_object['message']['cs3Label'] = 'target_group_arn'
                            json_object['message']['cs4'] = msg_arr[17].strip('"') if msg_arr[17] != '"-"' else ''
                            json_object['message']['cs4Label'] = 'trace_id'
                            json_object['message']['dhost'] = msg_arr[18].strip('"') if msg_arr[18] != '"-"' else ''
                            json_object['message']['cs5'] = msg_arr[19].strip('"') if msg_arr[19] != '"-"' else ''
                            json_object['message']['cs5Label'] = 'chosen_cert_arn'
                            json_object['message']['cn3'] = msg_arr[20] if msg_arr[20] != '"-"' else ''
                            json_object['message']['cn3Label'] = 'Matched_rule_priority'
                            json_object['message']['flexDate1'] = msg_arr[21] if msg_arr[21] != '"-"' else ''
                            json_object['message']['flexDate1Label'] = 'The time when the load balancer received the request from the client, in ISO 8601 format.'
                            json_object['message']['act'] = msg_arr[22].strip('"') if msg_arr[22] != '"-"' else ''
                            json_object['message']['cs6'] = msg_arr[23].strip('"') if msg_arr[23] != '"-"' else ''
                            json_object['message']['cs6Label'] = 'redirect_url'
                            
                            
                            
                            log = json.dumps(json_object)

                        elif json_object['metadata']['tags']['resource_type'] == 's3':
    
                            message = json_object['message']
                            
                            msg_arr = split_s3(message)
                            
                            json_object['message'] = {}
                            
                            json_object['message']['cs1'] = msg_arr[0] if msg_arr[0] != '-' else ''
                            json_object['message']['cs1Label'] = 'The canonical user ID of the owner of the source bucket.'
                            json_object['message']['cs2'] = msg_arr[1] if msg_arr[1] != '-' else ''
                            json_object['message']['cs2Label'] = 'The name of the bucket that the request was processed against.'
                            json_object['message']['cs3'] = msg_arr[2] if msg_arr[2] != '-' else ''
                            json_object['message']['cs3Label'] = 'The time at which the request was received; these dates and times are in Coordinated Universal Time (UTC)'
                            json_object['message']['src'] = msg_arr[3] if msg_arr[3] != '-' else ''
                            json_object['message']['cs4'] = msg_arr[4] if msg_arr[4] != '-' else ''
                            json_object['message']['cs4Label'] = 'The canonical user ID of the requester, or a - for unauthenticated requests.'
                            json_object['message']['cs5'] = msg_arr[5] if msg_arr[5] != '-' else ''
                            json_object['message']['cs5Label'] = 'A string generated by Amazon S3 to uniquely identify each request.'
                            json_object['message']['cs6'] = msg_arr[6] if msg_arr[6] != '-' else ''
                            json_object['message']['cs6Label'] = 'The operation listed here is declared as SOAP.operation, REST.HTTP_method.resource_type, WEBSITE.HTTP_method.resource_type, or BATCH.DELETE.OBJECT, or S3.action.resource_type.'
                            json_object['message']['flexString1'] = msg_arr[7] if msg_arr[7] != '-' else ''
                            json_object['message']['flexString1Label'] = 'The "key" part of the request, URL encoded, or "-" if the operation does not take a key parameter.'
                            json_object['message']['RequestMethod'] = msg_arr[8].split(' ')[0] if msg_arr[8] != '-' else ''
                            json_object['message']['Request'] = msg_arr[8].split(' ')[1] if msg_arr[8] != '-' else ''
                            json_object['message']['Outcome'] = msg_arr[9] if msg_arr[9] != '-' else ''
                            json_object['message']['ErrorCode'] = msg_arr[10] if msg_arr[10] != '-' else ''
                            json_object['message']['out'] = msg_arr[11] if msg_arr[11] != '-' else ''
                            json_object['message']['ObjectSize'] = msg_arr[12] if msg_arr[12] != '-' else ''
                            json_object['message']['cn1'] = msg_arr[13] if msg_arr[13] != '-' else ''
                            json_object['message']['cn1Label'] = 'The number of milliseconds the request was in flight from the server\'s perspective.'
                            json_object['message']['cn2'] = msg_arr[14] if msg_arr[14] != '-' else ''
                            json_object['message']['cn2Label'] = 'The number of milliseconds that Amazon S3 spent processing your request.'
                            json_object['message']['requestContext'] = msg_arr[15] if msg_arr[15] != '-' else ''
                            json_object['message']['requestClientApplication'] = msg_arr[16] if msg_arr[16] != '-' else ''
                            json_object['message']['flexString2'] = msg_arr[18] if msg_arr[18] != '-' else ''
                            json_object['message']['flexString2Label'] = 'The x-amz-id-2 or Amazon S3 extended request ID.'
                            json_object['message']['dhost'] = msg_arr[22] if msg_arr[22] != '-' else ''
                            json_object['message']['proto'] = msg_arr[23] if msg_arr[23] != '-' else ''
                            
                            log = json.dumps(json_object)

                        elif json_object['metadata']['tags']['resource_type'] == 'waf':
                            message = json_object['message']
                            message_object = json.loads(message)
                            
                            http_request = message_object['httpRequest']
                            headers = http_request['headers']
                            
                            dhost = ''
                            requestContext = ''
                            for header in headers:
                                if header['name'].lower() == 'host':
                                    dhost = header['value']
                                elif header['name'].lower() == 'referer':
                                    requestContext = header['value']
                            
                            json_object['message'] = {}
                            
                            json_object['message']['act'] = message_object['action'] if 'action' in message_object else ''
                            json_object['message']['src'] = http_request['clientIp'] if 'clientIp' in http_request else ''
                            json_object['message']['requestMethod'] = http_request['httpMethod'] if 'httpMethod' in http_request else ''
                            json_object['message']['request'] = http_request['uri'] if 'uri' in http_request else ''
                            json_object['message']['requestId'] = http_request['requestId'] if 'requestId' in http_request else ''
                            json_object['message']['cs1'] = http_request['country'] if 'country' in http_request else ''
                            json_object['message']['cs1Label'] = 'The source country of the request. If AWS WAF is unable to determine the country of origin, it sets this field to -.'
                            json_object['message']['cs2'] = message_object['ruleGroupList'] if 'ruleGroupList' in message_object else ''
                            json_object['message']['cs2Label'] = 'The list of rule groups that acted on this request.'
                            json_object['message']['cs3'] = message_object['terminatingRuleId'] if 'terminatingRuleId' in message_object else ''
                            json_object['message']['cs3Label'] = 'The ID of the rule that terminated the request. If nothing terminates the request, the value is Default_Action.'
                            json_object['message']['deviceCustomDate1'] = message_object['timestamp'] if 'timestamp' in message_object else ''
                            json_object['message']['deviceCustomDate1Label'] = 'Timestamp of the request.'
                            json_object['message']['dhost'] = dhost
                            json_object['message']['requestContext'] = requestContext
                            
                            log = json.dumps(json_object)
                        
                        elif json_object['metadata']['tags']['resource_type'] == 'cloudtrail':

                            message = json_object['message']
                            message_object = json.loads(message)
                            
                            json_object['message'] = {}
                            
                            json_object['message']['EventVersion'] = message_object['eventVersion'] if 'eventVersion' in message_object else ''
                            json_object['message']['UserIdentityType'] = message_object['userIdentity']['type'] if 'userIdentity' in message_object and 'type' in message_object['userIdentity'] else ''
                            json_object['message']['UserIdentityPrincipalId'] = message_object['userIdentity']['principalId'] if 'userIdentity' in message_object and 'principalId' in message_object['userIdentity'] else ''
                            json_object['message']['UserIdentityArn'] = message_object['userIdentity']['arn'] if 'userIdentity' in message_object and 'arn' in message_object['userIdentity'] else ''
                            json_object['message']['UserIdentityAccountId'] = message_object['userIdentity']['accountId'] if 'userIdentity' in message_object and 'accountId' in message_object['userIdentity'] else ''
                            json_object['message']['UserIdentityAccessKeyId'] = message_object['userIdentity']['accessKeyId'] if 'userIdentity' in message_object and 'accessKeyId' in message_object['userIdentity'] else ''
                            json_object['message']['SessionIssuerType'] = message_object['userIdentity']['sessionContext']['sessionIssuer']['type'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'sessionIssuer' in message_object['userIdentity']['sessionContext'] and 'type' in message_object['userIdentity']['sessionContext']['sessionIssuer'] else ''
                            json_object['message']['SessionIssuerPrincipalId'] = message_object['userIdentity']['sessionContext']['sessionIssuer']['principalId'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'sessionIssuer' in message_object['userIdentity']['sessionContext'] and 'principalId' in message_object['userIdentity']['sessionContext']['sessionIssuer'] else ''
                            json_object['message']['SessionIssuerArn'] = message_object['userIdentity']['sessionContext']['sessionIssuer']['arn'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'sessionIssuer' in message_object['userIdentity']['sessionContext'] and 'arn' in message_object['userIdentity']['sessionContext']['sessionIssuer'] else ''
                            json_object['message']['SessionIssuerAccountId'] = message_object['userIdentity']['sessionContext']['sessionIssuer']['accountId'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'sessionIssuer' in message_object['userIdentity']['sessionContext'] and 'accountId' in message_object['userIdentity']['sessionContext']['sessionIssuer'] else ''
                            json_object['message']['SessionIssuerUserName'] = message_object['userIdentity']['sessionContext']['sessionIssuer']['userName'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'sessionIssuer' in message_object['userIdentity']['sessionContext'] and 'userName' in message_object['userIdentity']['sessionContext']['sessionIssuer'] else ''
                            json_object['message']['SessionCreationDate'] = message_object['userIdentity']['sessionContext']['attributes']['creationDate'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'attributes' in message_object['userIdentity']['sessionContext'] and 'creationDate' in message_object['userIdentity']['sessionContext']['attributes'] else ''
                            json_object['message']['SessionMfaAuthenticated'] = message_object['userIdentity']['sessionContext']['attributes']['mfaAuthenticated'] if 'userIdentity' in message_object and 'sessionContext' in message_object['userIdentity'] and 'attributes' in message_object['userIdentity']['sessionContext'] and 'mfaAuthenticated' in message_object['userIdentity']['sessionContext']['attributes'] else ''
                            json_object['message']['EventSource'] = message_object['eventSource'] if 'eventSource' in message_object else ''
                            json_object['message']['EventName'] = message_object['eventName'] if 'eventName' in message_object else ''
                            json_object['message']['AWSRegion'] = message_object['awsRegion'] if 'awsRegion' in message_object else ''
                            json_object['message']['SourceAddress'] = message_object['sourceIPAddress'] if 'sourceIPAddress' in message_object else ''
                            json_object['message']['UserAgent'] = message_object['userAgent'] if 'userAgent' in message_object else ''
                            json_object['message']['RequestParamters'] = message_object['requestParamters'] if 'requestParamters' in message_object else ''
                            json_object['message']['AWSRequestId_'] = message_object['requestID'] if 'requestID' in message_object else ''
                            json_object['message']['AWSEventId'] = message_object['eventID'] if 'eventID' in message_object else ''
                            json_object['message']['ReadOnly'] = message_object['readOnly'] if 'readOnly' in message_object else ''
                            json_object['message']['EventTypeName'] = message_object['eventType'] if 'eventType' in message_object else ''
                            json_object['message']['ManagementEvent'] = message_object['managementEvent'] if 'managementEvent' in message_object else ''
                            json_object['message']['RecipientAccountId'] = message_object['recipientAccountId'] if 'recipientAccountId' in message_object else ''
                            json_object['message']['ErrorCode'] = message_object['errorCode'] if 'errorCode' in message_object else ''
                            json_object['message']['ErrorMessage'] = message_object['erorMessage'] if 'erorMessage' in message_object else ''
                            
                            log = json.dumps(json_object)

                        coreEvents.append(log)
                    else:
                        pass
                except ValueError as e:
                    pass

        if len(coreEvents) > 1000000:
            with sentinel:                                                        
                for event in coreEvents:
                    #if file_events % 1000 == 0:
                        #logging.info("{} events parsed.".format(file_events))
                    sentinel.send(event)
                    file_events += 1 
            failed_sent_events_number += sentinel.failed_sent_events_number
            successfull_sent_events_number += sentinel.successfull_sent_events_number
            del coreEvents
            coreEvents = []            
    
    #logging.info('Total number of files is {}'.format(len(coreEvents)))    


    with sentinel:                                                        
        for event in coreEvents:
            #if file_events % 1000 == 0:
                #logging.info("{} events parsed.".format(file_events))
            sentinel.send(event)
            file_events += 1 
    failed_sent_events_number += sentinel.failed_sent_events_number
    successfull_sent_events_number += sentinel.successfull_sent_events_number

    if failed_sent_events_number:
        logging.info('{} AWS S3 files have not been sent'.format(failed_sent_events_number))

    if successfull_sent_events_number:
        logging.info('Program finished. {} AWS S3 files have been sent.'.format(successfull_sent_events_number))

    if successfull_sent_events_number == 0 and failed_sent_events_number == 0:
        logging.info('No Fresh AWS S3 files')

    logging.info("{} logs failed to parse or were discarded".format(len(failedEvents)))


    logging.info("End Program")





"""========== End Runtime ==========="""

def convert_list_to_csv_line(ls):
    line = StringIO()
    writer = csv.writer(line)
    writer.writerow(ls)
    return line.getvalue()

class S3Client:
    def __init__(self, aws_access_key_id, aws_secret_acces_key, aws_region_name, aws_s3_bucket):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_acces_key = aws_secret_acces_key
        self.aws_region_name = aws_region_name
        self.aws_s3_bucket = self._get_s3_bucket_name(aws_s3_bucket)
        self.aws_s3_prefix = self._get_s3_prefix(aws_s3_bucket)        
        self.total_events = 0
        self.input_date_format = '%Y-%m-%d %H:%M:%S'
        self.output_date_format = '%Y-%m-%dT%H:%M:%SZ'

        self.s3 = boto3.client(
            's3',
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_acces_key,
            region_name=self.aws_region_name
        )       
       
    def _get_aws_account_id(self):
        self.sts = boto3.client(
            "sts", 
            aws_access_key_id=self.aws_access_key_id, 
            aws_secret_access_key=self.aws_secret_acces_key,
            region_name=self.aws_region_name
        )    
        return self.sts.get_caller_identity()["Account"]

    def _get_s3_bucket_name(self, aws_s3_bucket):
        aws_s3_bucket = self._normalize_aws_s3_bucket_string(aws_s3_bucket)
        tokens = aws_s3_bucket.split('/')
        aws_s3_bucket = tokens[0]
        return aws_s3_bucket

    def _get_s3_prefix(self, aws_s3_bucket):
        aws_s3_bucket = self._normalize_aws_s3_bucket_string(aws_s3_bucket)
        tokens = aws_s3_bucket.split('/')
        if len(tokens) > 1:
            prefix = '/'.join(tokens[1:]) + '/'
        else:
            prefix = ''
        return prefix

    def _normalize_aws_s3_bucket_string(self, aws_s3_bucket):
        aws_s3_bucket = aws_s3_bucket.strip()
        aws_s3_bucket = aws_s3_bucket.replace('s3://', '')
        if aws_s3_bucket.startswith('/'):
            aws_s3_bucket = aws_s3_bucket[1:]
        if aws_s3_bucket.endswith('/'):
            aws_s3_bucket = aws_s3_bucket[:-1]
        return aws_s3_bucket

    def get_time_interval(self):
        ts_from = datetime.datetime.utcnow() - datetime.timedelta(minutes=collection_schedule + 1)
        ts_to = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
        ts_from = ts_from.replace(tzinfo=datetime.timezone.utc, second=0, microsecond=0)
        ts_to = ts_to.replace(tzinfo=datetime.timezone.utc, second=0, microsecond=0)
        return ts_from, ts_to                   
    
    def _make_objects_list_request(self, marker='', prefix=''):
        if marker == '':
            response = self.s3.list_objects_v2(
            Bucket=self.aws_s3_bucket, 
            Prefix=prefix
            )
        else:
            response = self.s3.list_objects_v2(
            Bucket=self.aws_s3_bucket, 
            ContinuationToken=marker,
            Prefix=prefix
            )
        
        try:
            response_code = response.get('ResponseMetadata', {}).get('HTTPStatusCode', None)
            if response_code == 200:
                return response
            else:
                raise Exception('HTTP Response Code - {}'.format(response_code))
        except Exception as err:
            logging.error('Error while getting objects list - {}'.format(err))
            raise Exception

    def get_files_list(self, ts_from, ts_to):
        files = []
        folders = self.s3.list_objects(Bucket=self.aws_s3_bucket, Prefix=self.aws_s3_prefix, Delimiter='/')       

        marker_end = (ts_from - datetime.timedelta(minutes=60)).strftime("/%Y-%m-%d/%Y-%m-%d-%H-%M")
        
        for o in folders.get('CommonPrefixes'):
            prefix = o.get('Prefix')
            if "error" in prefix.lower():
                continue        
            marker = ""#o.get('Prefix') + s3_folder + marker_end   
            folder = o.get('Prefix') + s3_folder           
            while True:                
                response = self._make_objects_list_request(marker=marker, prefix=folder)
                for file_obj in response.get('Contents', []):
                    if ts_to > file_obj['LastModified'] >= ts_from:
                        files.append(file_obj)

                if response['IsTruncated'] is True:
                    marker = response['NextContinuationToken']
                else:
                    break

        return self.sort_files_by_date(files)

    def download_obj(self, key):
        logging.info('Started downloading {}'.format(key))
        res = self.s3.get_object(Bucket=self.aws_s3_bucket, Key=key)
        try:
            response_code = res.get('ResponseMetadata', {}).get('HTTPStatusCode', None)
            if response_code == 200:
                body = res['Body']
                data = body.read()
                logging.info('File {} downloaded'.format(key))
                return data
            else:
                logging.error('Error while getting object {}. HTTP Response Code - {}'.format(key, response_code))
        except Exception as err:
            logging.error('Error while getting object {} - {}'.format(key, err))

    def unpack_file(self, downloaded_obj, key):
        try:
            file_obj = io.BytesIO(downloaded_obj)
            if '.csv.gz' in key.lower():
                extracted_file = gzip.GzipFile(fileobj=file_obj).read().decode()
            elif '.json.gz' in key.lower():
                extracted_file = gzip.GzipFile(fileobj=file_obj)
            elif '.jsonl.gz' in key.lower():
                extracted_file = gzip.GzipFile(fileobj=file_obj).read().decode('utf-8')
            elif '.log.gz' in key.lower():
                extracted_file = gzip.GzipFile(fileobj=file_obj).read().decode('utf-8')                             
            elif '.json' in key.lower():
                extracted_file = file_obj
            return extracted_file

        except Exception as err:
            logging.error('Error while unpacking file {} - {}'.format(key, err))

    @staticmethod
    def convert_empty_string_to_null_values(d: dict):
        for k, v in d.items():
            if v == '' or (isinstance(v, list) and len(v) == 1 and v[0] == ''):
                d[k] = None
        return d
        
    @staticmethod
    def format_date(date_string, input_format, output_format):
        try:
            date = datetime.datetime.strptime(date_string, input_format)
            date_string = date.strftime(output_format)
        except Exception:
            pass
        return date_string    

    @staticmethod
    def sort_files_by_date(ls):
        return sorted(ls, key=lambda k: k['LastModified'])

    def process_obj(self, obj):        
        key = obj['Key']        
        if '.json.gz' in key.lower():
            downloaded_obj = self.download_obj(key)
            json_file = self.unpack_file(downloaded_obj, key)
            logEvents = json.load(json_file)['Records']
            sortedLogEvents = sorted(logEvents, key=lambda r: r['eventTime'])
        elif '.jsonl.gz' in key.lower():
            downloaded_obj = self.download_obj(key)
            json_file = self.unpack_file(downloaded_obj, key)
            sortedLogEvents = json_file.split('\n')
        elif '.csv.gz' in key.lower():
            downloaded_obj = self.download_obj(key)
            csv_file = self.unpack_file(downloaded_obj, key)
            sortedLogEvents = self.parse_csv_file(csv_file)
        elif '.log.gz' in key.lower():
            downloaded_obj = self.download_obj(key)
            csv_file = self.unpack_file(downloaded_obj, key)
            sortedLogEvents = self.parse_log_file(csv_file)
        elif '.json' in key.lower():
            downloaded_obj = self.download_obj(key)
            sortedLogEvents = self.unpack_file(downloaded_obj, key)    
        else:
            downloaded_obj = self.download_obj(key)
            sortedLogEvents = []
            try:
                sortedLogEvents = gzip.decompress(downloaded_obj).decode().split('\n')
            except:
                try:
                    sortedLogEvents = gzip.decompress(gzip.decompress(downloaded_obj)).decode().split('\n')
                except:
                    logging.error("Unable to process file: {}".format(key))               
            
        return sortedLogEvents

    def parse_csv_file(self, csv_file):
        csv_reader = csv.reader(csv_file.split('\n'), delimiter=',')
        for row in csv_reader:
            if len(row) > 1:
                if len(row) == 10:
                    event = {
                        'Timestamp': self.format_date(row[0], self.input_date_format, self.output_date_format),
                        'Policy Identity': row[1],
                        'Identities': row[2].split(','),
                        'InternalIp': row[3],
                        'ExternalIp': row[4],
                        'Action': row[5],
                        'QueryType': row[6],
                        'ResponseCode': row[7],
                        'Domain': row[8],
                        'Categories': row[9].split(',')
                    }
                    try:
                        event['Policy Identity Type'] = row[10]
                    except IndexError:
                        pass
                    try:
                        event['Identity Types'] = row[11].split(',')
                    except IndexError:
                        pass
                    try:
                        event['Blocked Categories'] = row[12].split(',')
                    except IndexError:
                        pass
                elif len(row) == 14:
                    event = {
                        'Timestamp': self.format_date(row[0], self.input_date_format, self.output_date_format),
                        'originId': row[1],
                        'Identity': row[2],
                        'Identity Type': row[3],
                        'Direction': row[4],
                        'ipProtocol': row[5],
                        'packetSize': row[6],
                        'sourceIp': row[7],
                        'sourcePort': row[8],
                        'destinationIp': row[9],
                        'destinationPort': row[10],
                        'dataCenter': row[11],
                        'ruleId': row[12],
                        'verdict': row[13]
                    }
                elif len(row) == 21:
                    event = {
                        'Timestamp': self.format_date(row[0], self.input_date_format, self.output_date_format),
                        'Identities': row[1],
                        'Internal IP': row[2],
                        'External IP': row[3],
                        'Destination IP': row[4],
                        'Content Type': row[5],
                        'Verdict': row[6],
                        'URL': row[7],
                        'Referer': row[8],
                        'userAgent': row[9],
                        'statusCode': row[10],
                        'requestSize': row[11],
                        'responseSize': row[12],
                        'responseBodySize': row[13],
                        'SHA-SHA256': row[14],
                        'Categories': row[15].split(','),
                        'AVDetections': row[16].split(','),
                        'PUAs': row[17].split(','),
                        'AMP Disposition': row[18],
                        'AMP Malware Name': row[19],
                        'AMP Score': row[20]
                    }
                    try:
                        event['Blocked Categories'] = row[21].split(',')
                    except IndexError:
                        pass

                    int_fields = [
                        'requestSize',
                        'responseSize',
                        'responseBodySize'
                    ]

                    for field in int_fields:
                        try:
                            event[field] = int(event[field])
                        except Exception:
                            pass                
                else:
                    event = {"message": convert_list_to_csv_line(row)}
                
                event = self.convert_empty_string_to_null_values(event)                
                yield event
                
    def parse_log_file(self, log_file):
        log_reader = csv.reader(log_file.split('\n'), delimiter=' ')        
        for row in log_reader:
            if len(row) > 1:
                if len(row) == 28: #Service name, traffic path, and flow direction
                    event = {                    
                        'version': row[0],
                        'srcaddr': row[1],
                        'dstaddr': row[2],
                        'srcport': row[3],
                        'dstport': row[4],
                        'protocol': row[5],
                        'start': row[6],
                        'end': row[7],
                        'type': row[8],
                        'packets': row[9],
                        'bytes': row[10],
                        'account-id': row[11],                    
                        'vpc-id': row[12],
                        'subnet-id': row[13],
                        'instance-id': row[14],
                        'region': row[15],
                        'az-id': row[16],
                        'sublocation-type': row[17],
                        'sublocation-id': row[18],
                        'action': row[19],
                        'tcp-flags': row[20],
                        'pkt-srcaddr': row[21],
                        'pkt-dstaddr': row[22],
                        'pkt-src-aws-service': row[23],
                        'pkt-dst-aws-service': row[24],
                        'traffic-path': row[25],
                        'flow-direction': row[26],
                        'log-status': row[27]                    
                    }                   
                elif len(row) == 6: #Traffic through a NAT gateway
                    event = {                    
                        'instance-id': row[0],
                        'interface-id': row[1],
                        'srcaddr': row[2],
                        'dstaddr': row[3],
                        'pkt-srcaddr': row[4],
                        'pkt-dstaddr': row[5]
                    }                    
                elif len(row) == 17: #Traffic through a transit gateway
                    event = {                    
                        'version': row[0],
                        'interface-id': row[1],
                        'account-id': row[2],
                        'vpc-id': row[3],
                        'subnet-id': row[4],
                        'instance-id': row[5],
                        'srcaddr': row[6],
                        'dstaddr': row[7],
                        'srcport': row[8],
                        'dstport': row[9],
                        'protocol': row[10],
                        'tcp-flags': row[11],                    
                        'type': row[12],
                        'pkt-srcaddr': row[13],
                        'pkt-dstaddr': row[14],
                        'action': row[15],
                        'log-status': row[16]
                    }                    
                elif len(row) == 21: #TCP flag sequence
                    event = {                    
                        'version': row[0],
                        'vpc-id': row[1],
                        'subnet-id': row[2],
                        'instance-id': row[3],
                        'interface-id': row[4],
                        'account-id': row[5],
                        'type': row[6],
                        'srcaddr': row[7],
                        'dstaddr': row[8],
                        'srcport': row[9],
                        'dstport': row[10],
                        'pkt-srcaddr': row[11],                    
                        'pkt-dstaddr': row[12],
                        'protocol': row[13],
                        'bytes': row[14],
                        'packets': row[15],
                        'start': row[16],
                        'end': row[17],
                        'action': row[18],
                        'tcp-flags': row[19],
                        'log-status': row[20]
                    }                    
                elif len(row) == 14: 
                    #Accepted and rejected traffic; No data and skipped records
                    #Security group and network ACL rules; IPv6 traffic
                    event = {                    
                        'version': row[0],
                        'account-id': row[1],
                        'interface-id': row[2],
                        'srcaddr': row[3],
                        'dstaddr': row[4],
                        'srcport': row[5],
                        'dstport': row[6],
                        'protocol': row[7],
                        'packets': row[8],
                        'bytes': row[9],
                        'start': row[10],
                        'end': row[11],                    
                        'action': row[12],
                        'log-status': row[13]                        
                    }                    
                else:
                    event = {"message": convert_list_to_csv_line(row)}

                event = self.convert_empty_string_to_null_values(event)                
                yield event


class AzureSentinelConnector:
    def __init__(self, log_analytics_uri, customer_id, shared_key, log_type, queue_size=200, bulks_number=10, queue_size_bytes=25 * (2**20)):
        self.log_analytics_uri = log_analytics_uri
        self.customer_id = customer_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.queue_size = queue_size
        self.bulks_number = bulks_number
        self.queue_size_bytes = queue_size_bytes
        self._queue = []
        self._bulks_list = []
        self.successfull_sent_events_number = 0
        self.failed_sent_events_number = 0

    def send(self, event):
        self._queue.append(event)
        if len(self._queue) >= self.queue_size:
            self.flush(force=False)

    def flush(self, force=True):
        self._bulks_list.append(self._queue)
        if force:
            self._flush_bulks()
        else:
            if len(self._bulks_list) >= self.bulks_number:
                self._flush_bulks()

        self._queue = []

    def _flush_bulks(self):
        jobs = []
        for queue in self._bulks_list:
            if queue:
                queue_list = self._split_big_request(queue)
                for q in queue_list:
                    jobs.append(Thread(target=self._post_data, args=(self.customer_id, self.shared_key, q, self.log_type, )))

        for job in jobs:
            job.start()

        for job in jobs:
            job.join()
        logging.info('{} events have been successfully sent to Azure Sentinel'.format(self.successfull_sent_events_number))
        logging.error("{} events have failed sending to Azure Sentinel".format(self.failed_sent_events_number))
        self._bulks_list = []

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self.flush()

    def _build_signature(self, customer_id, shared_key, date, content_length, method, content_type, resource):
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
        return authorization

    def _post_data(self, customer_id, shared_key, body, log_type):
        events_number = len(body)
        body = json.dumps(body)
        #body = re.sub(r'\\', '', body)
        #body = re.sub(r'"{', '{', body)
        #body = re.sub(r'}"', '}', body)
        body = body.replace('\\\\','\\')
        body = body.replace('["{','[{')
        body = body.replace('}"]','}]')
        body = body.replace('", "',', ')
        
        temp = ""
        for i in range(len(body)):
            if body[i] == "\\":
                if body[i+1] == "\\":
                    temp = temp + "\\"
                    i += 1
            else:
                temp = temp + body[i]
        body = temp
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        signature = self._build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = self.log_analytics_uri + resource + '?api-version=2016-04-01'
        
        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        response = requests.post(uri, data=body, headers=headers)
        #print("Response Code: {}".format(response.status_code))
        #sys.stdout.flush()
        #logging.info("Response Code: {}".format(response.status_code))
        #logging.info("Response Text: {}".format(response.text))
        if (response.status_code >= 200 and response.status_code <= 299):
            logging.info('{} events have been successfully sent to Azure Sentinel'.format(events_number))
            self.successfull_sent_events_number += events_number
        else:
            logging.error("Error during sending events to Azure Sentinel. Response code: {}".format(response.status_code))
            self.failed_sent_events_number += events_number
        

    def _check_size(self, queue):
        data_bytes_len = len(json.dumps(queue).encode())
        return data_bytes_len < self.queue_size_bytes

    def _split_big_request(self, queue):
        if self._check_size(queue):
            return [queue]
        else:
            middle = int(len(queue) / 2)
            queues_list = [queue[:middle], queue[middle:]]
            return self._split_big_request(queues_list[0]) + self._split_big_request(queues_list[1])
