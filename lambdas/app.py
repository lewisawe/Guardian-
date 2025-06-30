import json
import os
import uuid
import time
import base64
import hashlib
import urllib.request
import urllib.parse
import boto3
from datetime import datetime, timedelta

# Initialize AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Get environment variables
S3_BUCKET = os.environ.get('S3_BUCKET')
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE')
table = dynamodb.Table(DYNAMODB_TABLE)

def lambda_handler(event, context):
    """
    Main handler for the Guardian Lambda function.
    Processes both file uploads and URL submissions.
    """
    try:
        # Determine if this is a file or URL analysis request
        path = event.get('path', '')
        
        if '/analyze/file' in path:
            return handle_file_analysis(event)
        elif '/analyze/url' in path:
            return handle_url_analysis(event)
        else:
            return {
                'statusCode': 400,
                'headers': get_cors_headers(),
                'body': json.dumps({'error': 'Invalid request path'})
            }
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': get_cors_headers(),
            'body': json.dumps({'error': 'Internal server error'})
        }

def handle_file_analysis(event):
    """
    Handle file upload and analysis.
    """
    try:
        # Generate a unique ID for this analysis
        analysis_id = str(uuid.uuid4())
        
        # Parse the request body
        body = event.get('body', '')
        is_base64 = event.get('isBase64Encoded', False)
        
        if is_base64:
            body = base64.b64decode(body)
        
        # Save the file to S3 temporarily
        file_key = f"uploads/{analysis_id}"
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=file_key,
            Body=body
        )
        
        # Perform analysis on the file
        analysis_results = analyze_file(S3_BUCKET, file_key)
        
        # Store results in DynamoDB
        store_results(analysis_id, analysis_results)
        
        # Clean up - delete the file from S3
        s3_client.delete_object(
            Bucket=S3_BUCKET,
            Key=file_key
        )
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps(analysis_results)
        }
    except Exception as e:
        print(f"Error in file analysis: {str(e)}")
        return {
            'statusCode': 500,
            'headers': get_cors_headers(),
            'body': json.dumps({'error': 'Error processing file'})
        }

def handle_url_analysis(event):
    """
    Handle URL submission and analysis.
    """
    try:
        # Generate a unique ID for this analysis
        analysis_id = str(uuid.uuid4())
        
        # Parse the request body
        body = event.get('body', '')
        if event.get('isBase64Encoded', False):
            body = base64.b64decode(body).decode('utf-8')
        
        request_data = json.loads(body)
        url = request_data.get('url')
        
        if not url:
            return {
                'statusCode': 400,
                'headers': get_cors_headers(),
                'body': json.dumps({'error': 'URL is required'})
            }
        
        # Perform analysis on the URL
        analysis_results = analyze_url(url)
        
        # Store results in DynamoDB
        store_results(analysis_id, analysis_results)
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps(analysis_results)
        }
    except Exception as e:
        print(f"Error in URL analysis: {str(e)}")
        return {
            'statusCode': 500,
            'headers': get_cors_headers(),
            'body': json.dumps({'error': 'Error processing URL'})
        }

def analyze_file(bucket, key):
    """
    Analyze a file stored in S3.
    """
    # Get the file from S3
    response = s3_client.get_object(Bucket=bucket, Key=key)
    file_content = response['Body'].read()
    
    # Calculate file hashes
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha1_hash = hashlib.sha1(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    
    # Get file metadata
    file_size = len(file_content)
    content_type = response.get('ContentType', 'application/octet-stream')
    
    # Perform basic file analysis
    # In a real implementation, you would add more sophisticated analysis here
    # such as virus scanning, file type verification, etc.
    
    return {
        'analysis_type': 'file',
        'timestamp': datetime.utcnow().isoformat(),
        'file_info': {
            'size': file_size,
            'content_type': content_type,
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
        },
        'risk_assessment': {
            'score': 0,  # Placeholder for actual risk scoring
            'findings': []  # Placeholder for security findings
        }
    }

def analyze_url(url):
    """
    Analyze a URL.
    """
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Basic URL validation
    if not parsed_url.scheme or not parsed_url.netloc:
        return {
            'analysis_type': 'url',
            'timestamp': datetime.utcnow().isoformat(),
            'url': url,
            'error': 'Invalid URL format'
        }
    
    try:
        # Fetch URL headers (without downloading the full content)
        req = urllib.request.Request(url, method='HEAD')
        response = urllib.request.urlopen(req, timeout=5)
        
        # Get HTTP status and headers
        status_code = response.getcode()
        headers = dict(response.getheaders())
        
        # In a real implementation, you would add more sophisticated analysis here
        # such as reputation checking, content analysis, etc.
        
        return {
            'analysis_type': 'url',
            'timestamp': datetime.utcnow().isoformat(),
            'url': url,
            'url_info': {
                'domain': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'scheme': parsed_url.scheme
            },
            'http_info': {
                'status_code': status_code,
                'headers': headers
            },
            'risk_assessment': {
                'score': 0,  # Placeholder for actual risk scoring
                'findings': []  # Placeholder for security findings
            }
        }
    except Exception as e:
        return {
            'analysis_type': 'url',
            'timestamp': datetime.utcnow().isoformat(),
            'url': url,
            'error': str(e)
        }

def store_results(analysis_id, results):
    """
    Store analysis results in DynamoDB.
    """
    # Set TTL for 7 days from now
    ttl = int((datetime.utcnow() + timedelta(days=7)).timestamp())
    
    # Store the results
    table.put_item(
        Item={
            'id': analysis_id,
            'results': results,
            'ttl': ttl
        }
    )
    
    return analysis_id

def get_cors_headers():
    """
    Return CORS headers for API responses.
    """
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Content-Type': 'application/json'
    }
