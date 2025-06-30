import json
import os
import uuid
import time
import base64
import hashlib
import urllib.request
import urllib.parse
import boto3
import re
import math
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Initialize AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Get environment variables
S3_BUCKET = os.environ.get('S3_BUCKET')
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE')
table = dynamodb.Table(DYNAMODB_TABLE)

# Common file signatures for detection
FILE_SIGNATURES = {
    b'%PDF': 'application/pdf',
    b'PK\x03\x04': 'application/zip',
    b'\x50\x4b\x03\x04': 'application/zip',
    b'MZ': 'application/x-msdownload',
    b'\xff\xd8\xff': 'image/jpeg',
    b'\x89PNG': 'image/png',
    b'GIF8': 'image/gif',
    b'BM': 'image/bmp',
    b'<?xml': 'application/xml',
    b'<!DOCTYPE html': 'text/html',
    b'<html': 'text/html',
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.msi', 
    '.scr', '.hta', '.com', '.pif', '.reg', '.vbe', '.wsf', '.wsh', '.msh'
]

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r'login|signin|account|password|credential|bank|verify|secure|auth',
    r'paypal|apple|microsoft|google|facebook|amazon|netflix|update|security',
    r'confirm|verify|validate|alert|notice|access|limited|unusual|activity',
    r'phish|malware|trojan|virus|malicious|hack|threat|attack|compromise'
]

# Malicious domains list (example - you would want to expand this)
MALICIOUS_DOMAINS = [
    'evil.example.com',
    'malware.example.org',
    'phishing.example.net'
]

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
    
    # Detect file type based on content
    detected_type = detect_file_type(file_content)
    
    # Check if file type matches content type
    type_mismatch = not content_type_matches(detected_type, content_type)
    
    # Extract filename from key if available
    filename = key.split('/')[-1]
    file_extension = os.path.splitext(filename)[1].lower() if '.' in filename else ''
    
    # Check for suspicious file extension
    is_suspicious_extension = file_extension in SUSPICIOUS_EXTENSIONS
    
    # Perform basic content analysis
    content_analysis = analyze_file_content(file_content, detected_type)
    
    # Calculate risk score
    risk_score = 0
    findings = []
    
    # Check for type mismatch
    if type_mismatch:
        risk_score += 40
        findings.append({
            'severity': 'MEDIUM',
            'type': 'FILE_TYPE_MISMATCH',
            'description': f"Declared type '{content_type}' doesn't match detected type '{detected_type}'"
        })
    
    # Check for suspicious extension
    if is_suspicious_extension:
        risk_score += 30
        findings.append({
            'severity': 'MEDIUM',
            'type': 'SUSPICIOUS_EXTENSION',
            'description': f"File has a potentially dangerous extension: {file_extension}"
        })
    
    # Add findings from content analysis
    if content_analysis.get('findings'):
        findings.extend(content_analysis['findings'])
        risk_score = max(risk_score, content_analysis.get('risk_score', risk_score))
    
    return {
        'analysis_type': 'file',
        'timestamp': datetime.utcnow().isoformat(),
        'file_info': {
            'size': file_size,
            'content_type': content_type,
            'detected_type': detected_type,
            'filename': filename,
            'extension': file_extension,
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
        },
        'content_analysis': content_analysis,
        'risk_assessment': {
            'score': risk_score,
            'findings': findings
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
    
    # Initialize risk assessment
    risk_score = 0
    findings = []
    
    # Check domain against known malicious domains
    domain = parsed_url.netloc.lower()
    if domain in MALICIOUS_DOMAINS:
        risk_score += 100
        findings.append({
            'severity': 'HIGH',
            'type': 'MALICIOUS_DOMAIN',
            'description': f"Domain '{domain}' is known to be malicious"
        })
    
    # Check for suspicious URL patterns
    url_lower = url.lower()
    suspicious_patterns = []
    for pattern in SUSPICIOUS_URL_PATTERNS:
        matches = re.findall(pattern, url_lower)
        if matches:
            suspicious_patterns.extend(matches)
    
    if suspicious_patterns:
        pattern_score = min(50, len(suspicious_patterns) * 10)
        risk_score += pattern_score
        findings.append({
            'severity': 'MEDIUM',
            'type': 'SUSPICIOUS_URL_PATTERN',
            'description': f"URL contains suspicious patterns: {', '.join(set(suspicious_patterns))}"
        })
    
    # Check for excessive subdomains
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        risk_score += 20
        findings.append({
            'severity': 'LOW',
            'type': 'EXCESSIVE_SUBDOMAINS',
            'description': f"URL contains an unusual number of subdomains ({subdomain_count})"
        })
    
    # Check for URL obfuscation techniques
    if '@' in url:
        risk_score += 30
        findings.append({
            'severity': 'MEDIUM',
            'type': 'URL_OBFUSCATION',
            'description': "URL contains @ symbol, which can be used for obfuscation"
        })
    
    if '%' in url and any(x in url for x in ['%3A', '%2F', '%40']):
        risk_score += 30
        findings.append({
            'severity': 'MEDIUM',
            'type': 'URL_OBFUSCATION',
            'description': "URL contains encoded characters that may be used for obfuscation"
        })
    
    # Check for IP address instead of domain name
    ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(ip_pattern, domain):
        risk_score += 30
        findings.append({
            'severity': 'MEDIUM',
            'type': 'IP_URL',
            'description': "URL uses an IP address instead of a domain name"
        })
    
    try:
        # Fetch URL headers (without downloading the full content)
        req = urllib.request.Request(url, method='HEAD')
        response = urllib.request.urlopen(req, timeout=5)
        
        # Get HTTP status and headers
        status_code = response.getcode()
        headers = dict(response.getheaders())
        
        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-Content-Type-Options': False,
            'X-Frame-Options': False,
            'X-XSS-Protection': False
        }
        
        for header in security_headers:
            if header in headers:
                security_headers[header] = True
        
        # Calculate security header score
        missing_headers = [h for h, present in security_headers.items() if not present]
        if missing_headers:
            risk_score += min(20, len(missing_headers) * 5)
            findings.append({
                'severity': 'LOW',
                'type': 'MISSING_SECURITY_HEADERS',
                'description': f"Missing security headers: {', '.join(missing_headers)}"
            })
        
        # Try to get content type
        content_type = headers.get('Content-Type', '')
        
        # Check for redirect
        is_redirect = 300 <= status_code < 400
        if is_redirect and 'Location' in headers:
            redirect_url = headers['Location']
            findings.append({
                'severity': 'INFO',
                'type': 'REDIRECT',
                'description': f"URL redirects to: {redirect_url}"
            })
        
        return {
            'analysis_type': 'url',
            'timestamp': datetime.utcnow().isoformat(),
            'url': url,
            'url_info': {
                'domain': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'scheme': parsed_url.scheme,
                'suspicious_patterns': suspicious_patterns if suspicious_patterns else None
            },
            'http_info': {
                'status_code': status_code,
                'headers': headers,
                'is_redirect': is_redirect,
                'security_headers': security_headers
            },
            'risk_assessment': {
                'score': risk_score,
                'findings': findings
            }
        }
    except Exception as e:
        # If we can't connect, add that to the findings
        risk_score += 10
        findings.append({
            'severity': 'LOW',
            'type': 'CONNECTION_ERROR',
            'description': f"Error connecting to URL: {str(e)}"
        })
        
        return {
            'analysis_type': 'url',
            'timestamp': datetime.utcnow().isoformat(),
            'url': url,
            'url_info': {
                'domain': parsed_url.netloc,
                'path': parsed_url.path,
                'query': parsed_url.query,
                'scheme': parsed_url.scheme,
                'suspicious_patterns': suspicious_patterns if suspicious_patterns else None
            },
            'error': str(e),
            'risk_assessment': {
                'score': risk_score,
                'findings': findings
            }
        }

def detect_file_type(file_content):
    """
    Detect file type based on content using signatures.
    """
    # Check file signatures
    for signature, mime_type in FILE_SIGNATURES.items():
        if file_content.startswith(signature):
            return mime_type
    
    # Check if it's text
    try:
        file_content[:1024].decode('utf-8')
        return 'text/plain'
    except UnicodeDecodeError:
        pass
    
    return 'application/octet-stream'

def content_type_matches(detected_type, declared_type):
    """
    Check if detected content type matches declared content type.
    """
    if not declared_type or declared_type == 'application/octet-stream':
        return True
    
    # Normalize types for comparison
    detected_base = detected_type.split(';')[0].strip().lower()
    declared_base = declared_type.split(';')[0].strip().lower()
    
    # Exact match
    if detected_base == declared_base:
        return True
    
    # Check for compatible types
    if detected_base == 'text/plain' and declared_base.startswith('text/'):
        return True
    
    # Check for generic types
    if declared_base == 'application/octet-stream':
        return True
    
    return False

def analyze_file_content(file_content, content_type):
    """
    Analyze file content based on its type.
    """
    findings = []
    risk_score = 0
    analysis = {}
    
    # Check for executable content
    if content_type in ['application/x-msdownload', 'application/x-executable']:
        risk_score += 50
        findings.append({
            'severity': 'HIGH',
            'type': 'EXECUTABLE_CONTENT',
            'description': "File contains executable code"
        })
    
    # Check for scripts in text files
    if content_type.startswith('text/'):
        try:
            text_content = file_content.decode('utf-8', errors='ignore')
            
            # Check for script tags
            script_tags = re.findall(r'<script[^>]*>(.*?)</script>', text_content, re.DOTALL | re.IGNORECASE)
            if script_tags:
                risk_score += 30
                findings.append({
                    'severity': 'MEDIUM',
                    'type': 'EMBEDDED_SCRIPTS',
                    'description': f"File contains {len(script_tags)} script blocks"
                })
            
            # Check for suspicious JavaScript patterns
            js_patterns = [
                r'eval\s*\(', r'document\.write\s*\(', r'fromCharCode', r'String\.fromCharCode',
                r'unescape\s*\(', r'decrypt', r'encode', r'decode', r'atob\s*\(', r'btoa\s*\(',
                r'base64', r'exec\s*\(', r'Function\s*\(', r'setTimeout\s*\(', r'setInterval\s*\('
            ]
            
            js_matches = []
            for pattern in js_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    js_matches.append(pattern.replace(r'\s*\(', '()').replace(r'\\', '\\'))
            
            if js_matches:
                risk_score += min(40, len(js_matches) * 10)
                findings.append({
                    'severity': 'MEDIUM',
                    'type': 'SUSPICIOUS_JS_PATTERNS',
                    'description': f"File contains suspicious JavaScript patterns: {', '.join(js_matches)}"
                })
            
            # Calculate entropy for obfuscation detection
            char_count = {}
            for char in text_content:
                if char in char_count:
                    char_count[char] += 1
                else:
                    char_count[char] = 1
            
            entropy = 0
            for count in char_count.values():
                freq = count / len(text_content)
                entropy -= freq * math.log2(freq) if freq > 0 else 0
            
            if entropy > 5.7:  # Threshold for potentially obfuscated content
                risk_score += 30
                findings.append({
                    'severity': 'MEDIUM',
                    'type': 'POSSIBLE_OBFUSCATION',
                    'description': f"File contains potentially obfuscated content (entropy: {entropy:.2f})"
                })
            
            analysis['text_analysis'] = {
                'script_tags': len(script_tags) if script_tags else 0,
                'suspicious_patterns': js_matches if js_matches else None,
                'entropy': entropy
            }
        except Exception as e:
            print(f"Error analyzing text content: {str(e)}")
    
    # Check for PDF content
    if content_type == 'application/pdf':
        # Look for JavaScript in PDF
        if b'/JavaScript' in file_content or b'/JS' in file_content:
            risk_score += 40
            findings.append({
                'severity': 'MEDIUM',
                'type': 'PDF_WITH_JAVASCRIPT',
                'description': "PDF file contains JavaScript"
            })
        
        # Look for embedded files in PDF
        if b'/EmbeddedFile' in file_content or b'/EmbeddedFiles' in file_content:
            risk_score += 30
            findings.append({
                'severity': 'MEDIUM',
                'type': 'PDF_WITH_EMBEDDED_FILES',
                'description': "PDF file contains embedded files"
            })
    
    # Check for ZIP content
    if content_type == 'application/zip':
        # Check for potential zip bombs (very small file with high compression ratio)
        if len(file_content) < 1000 and len(file_content) > 0:
            risk_score += 20
            findings.append({
                'severity': 'LOW',
                'type': 'POTENTIAL_ZIP_BOMB',
                'description': "Small ZIP file detected, potential zip bomb"
            })
    
    # Add risk score and findings to the analysis
    analysis['risk_score'] = risk_score
    analysis['findings'] = findings
    
    return analysis

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
