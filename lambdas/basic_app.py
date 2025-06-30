import json

def lambda_handler(event, context):
    """
    Basic handler that just returns success without doing any analysis.
    """
    try:
        # Print the event for debugging
        print(f"Received event: {json.dumps(event)}")
        
        # Determine if this is a file or URL analysis request
        path = event.get('path', '')
        
        if '/analyze/file' in path:
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'analysis_type': 'file',
                    'message': 'File analysis successful (basic version)',
                    'risk_assessment': {
                        'score': 0,
                        'findings': []
                    }
                })
            }
        elif '/analyze/url' in path:
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'analysis_type': 'url',
                    'message': 'URL analysis successful (basic version)',
                    'risk_assessment': {
                        'score': 0,
                        'findings': []
                    }
                })
            }
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
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }

def get_cors_headers():
    """
    Return CORS headers for API responses.
    """
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'POST,OPTIONS,GET',
        'Content-Type': 'application/json'
    }
