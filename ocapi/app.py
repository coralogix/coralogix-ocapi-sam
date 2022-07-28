import logging
from sys import intern
import time
import urllib.request as urlrequest
import urllib.error as urlerror
import urllib.parse as urlparse
import json
import os, base64
from datetime import datetime, timezone, timedelta
from coralogix.handlers import CoralogixLogger
import boto3
from boto3.dynamodb.conditions import Key

# Create internal logger and logs logger.
internal_logger = logging.getLogger('Internal Logger')
internal_logger.setLevel(logging.INFO)
external_logger = logging.getLogger('External Logger')
external_logger.setLevel(logging.INFO)
external_logger.propagate = False
# Define environment variables
PRIVATE_KEY = os.getenv('CORALOGIX_PRIVATE_KEY')
APP_NAME = os.getenv('CORALOGIX_APPLICATION_NAME')
SUB_SYSTEM = os.getenv('CORALOGIX_SUBSYSTEM_NAME')
ENDPOINT = os.getenv('OCAPI_ENDPOINT')
LOGS_TO_STDOUT = os.getenv('LOGS_TO_STDOUT', 'True')
SELECT_STATEMENT = os.getenv('SELECT_STATEMENT')
USERNAME = os.getenv('OCAPI_USERNAME')
PASSWORD = os.getenv('OCAPI_PASSWORD')
DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE')
TRUE_VALUES = ['True','true']

def lambda_handler(event, context):
    internal_logger.info('OCAPI puller lambda - init')
    # Coralogix variables check
    if PRIVATE_KEY == '':
        internal_logger.error('OCAPI puller lambda Failure - coralogix private key not found')
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - coralogix private key not found',
            }),
        }
    if APP_NAME == '' or SUB_SYSTEM == '':
        internal_logger.error('OCAPI puller lambda Failure - coralogix application name and subsystem name not found')
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - coralogix application name and subsystem name not found',
            }),
        }
    # print to stdout/cloudwatch external logger's logs
    if LOGS_TO_STDOUT in TRUE_VALUES:
        external_logger.propagate = True
    # Coralogix Logger init
    coralogix_external_handler = CoralogixLogger(PRIVATE_KEY, APP_NAME, SUB_SYSTEM)
    # Add coralogix logger as a handler to the standard Python logger.
    external_logger.addHandler(coralogix_external_handler)
    # Environment variables check
    if ENDPOINT == '':
        internal_logger.error('OCAPI puller lambda Failure - Endpoint not found')
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - Endpoint not found',
            }),
        }
    if USERNAME == '' or PASSWORD == '':
        internal_logger.error('OCAPI puller lambda Failure - OCAPI username and password not found')
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - OCAPI username and password not found',
            }),
        }
    if SELECT_STATEMENT == '':
        internal_logger.error('OCAPI puller lambda Failure - select_statement not found')
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - select_statement not found',
            }),
        } 
    if DYNAMODB_TABLE is None or DYNAMODB_TABLE == '':
        internal_logger.error('OCAPI puller lambda Failure - dynamoDB not found')
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - dynamoDB not found',
            }),
        }   
    internal_logger.info('OCAPI puller lambda - init complete')
    access_token = get_token()
    # check if failed to get token
    if isinstance(access_token, dict):
        return access_token
    domain = ENDPOINT.split('/')[2]
    # Create the request with all its parameters
    request_body ={ 
        'count' : 200,
        'query' : { 
            'filtered_query': {
                'filter': {
                    'range_filter': { 	
                        'field': 'creation_date',
                        'from':'',
                        'to':''
                    }
                },
                'query' : {
                    'match_all_query': {}
                }
            }
        },
        'sorts' : [{'field':'creation_date', 'sort_order':'asc'}]
    }
    request_body['select'] = SELECT_STATEMENT
    # timeframe and dynamodb logic   
    dynamodb = boto3.resource('dynamodb')
    db_table = dynamodb.Table(DYNAMODB_TABLE)   
    response = db_table.scan()
    if 'Items' in response and len(response['Items']) > 0:
        last_update = response['Items'][0]['lastUpdate']
        cur_update = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        db_table.delete_item(Key={'lastUpdate':last_update})
        db_table.put_item(Item={'lastUpdate':cur_update})
    else:
        # key not found create a new one
        internal_logger.info('OCAPI puller lambda - DynamoDB Key not found, creating a new one')
        last_update = (datetime.now(timezone.utc)-timedelta(minutes=10)).isoformat().replace('+00:00', 'Z')
        cur_update = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        db_table.put_item(Item={'lastUpdate':cur_update})
    request_body['query']['filtered_query']['filter']['range_filter']['from'] = last_update
    request_body['query']['filtered_query']['filter']['range_filter']['to'] = cur_update
    request = urlrequest.Request(ENDPOINT,method='POST')
    request.add_header('Authorization','Bearer %s' % access_token)
    request.add_header('Content-Type', 'application/json')
    request.data = json.dumps(request_body).encode('utf-8')
    request.add_header('User-Agent', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0')
    request.add_header('host',domain)
    try:
        response = urlrequest.urlopen(request, timeout=15)
        # Send the body of the response to coralogix
        log_sender(response)
    except urlerror.HTTPError as e:
        internal_logger.error('OCAPI puller lambda Failure - Endpoint: %s , error: %s' % (ENDPOINT, e))
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - Endpoint: %s , error: %s' % (ENDPOINT, e)
            }),
        }
    except urlerror.URLError as e:
        internal_logger.error('OCAPI puller lambda Failure - Endpoint: %s , error: %s' % (ENDPOINT, e))
        return {
            'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - Endpoint: %s , error: %s' % (ENDPOINT, e)
            }),
        }
    CoralogixLogger.flush_messages()
    time.sleep(5) # for now until fixing python sdk not fully flushing within aws lambda
    internal_logger.info('OCAPI puller lambda Success - logs sent to coralogix')
    return {
    'statusCode': 200,
    'body': json.dumps({
    'message': 'OCAPI puller lambda Success - logs sent to coralogix',
    }),
    }

def log_sender(response):
    res_body_decoded = response.read().decode('utf-8')
    res_json = json.loads(res_body_decoded)
    # check for errors
    if 'fault' in res_json:
        external_logger.error(res_json['message'])
        return
    if 'total' in res_json and res_json['total'] > 0:
        external_logger.info('OCAPI puller lambda - Total number of hits: %s' % res_json['total'])
        for hit in res_json['hits']:
            external_logger.info(json.dumps(hit))
    else:
        external_logger.info('OCAPI puller lambda - No hits found')

def get_token():
    s = ('%s:%s' % (USERNAME, PASSWORD))
    s = s.encode()
    encoded_auth =  base64.b64encode(s).decode('utf-8')
    req_data = urlparse.urlencode({'grant_type': 'client_credentials'})
    req_data = req_data.encode('utf-8')
    request = urlrequest.Request('https://account.demandware.com/dw/oauth2/access_token',req_data)
    # adding charset parameter to the Content-Type header.
    request.add_header('Authorization','Basic %s' % encoded_auth)
    request.add_header('Content-Type', 'application/x-www-form-urlencoded;charset=utf-8')
    request.add_header('User-Agent', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0')
    try:
        response = urlrequest.urlopen(request, timeout=15)
    except urlerror.HTTPError as e:
        internal_logger.error('OCAPI puller lambda Failure - Error while getting token, Error: %s' % e)
        return {
           'statusCode': e.code,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - Error while getting token, Error: %s' % e,
        }),
        }
    except urlerror.URLError as e:
        internal_logger.error('OCAPI puller lambda Failure - Error while getting token, Error: %s' % e)
        return {
           'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - Error while getting token, Error: %s' % e,
        }),
        }
    res_body = response.read()
    try:
        JSON_object = json.loads(res_body.decode('utf-8'))
        access_token = JSON_object['access_token']
        return access_token
    except (ValueError,KeyError):
        internal_logger.error('OCAPI puller lambda Failure - Error while getting token, failed to get access_token from response - %s ' % json.dumps(JSON_object))
        return {
           'statusCode': 400,
            'body': json.dumps({
            'message': 'OCAPI puller lambda Failure - Error while getting token, failed to get access_token from request - %s ' % json.dumps(JSON_object),
        }),
        }