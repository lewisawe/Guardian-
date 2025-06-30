# Manual Deployment Guide for Guardianλ

This guide provides step-by-step instructions for deploying the Guardianλ infrastructure using AWS CLI commands instead of the provided Terraform scripts.

## Step 1: Set up environment variables

```bash
# Set your preferred AWS region
AWS_REGION="us-west-2"
# Generate unique names for resources
BUCKET_PREFIX="guardian-analysis-$(date +%s)"
WEB_UI_BUCKET_PREFIX="guardian-web-ui-$(date +%s)"
```

## Step 2: Create S3 bucket for temporary file storage

```bash
# Create analysis bucket
aws s3api create-bucket \
  --bucket "$BUCKET_PREFIX" \
  --region "$AWS_REGION"

# Block public access
aws s3api put-public-access-block \
  --bucket "$BUCKET_PREFIX" \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Set lifecycle policy to delete files after 1 day
aws s3api put-bucket-lifecycle-configuration \
  --bucket "$BUCKET_PREFIX" \
  --lifecycle-configuration '{
    "Rules": [
      {
        "ID": "delete-after-1-day",
        "Status": "Enabled",
        "Expiration": {
          "Days": 1
        }
      }
    ]
  }'
```

## Step 3: Create DynamoDB table for analysis results

```bash
aws dynamodb create-table \
  --table-name "GuardianAnalysisResults" \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "$AWS_REGION"

# Enable TTL on the table
aws dynamodb update-time-to-live \
  --table-name "GuardianAnalysisResults" \
  --time-to-live-specification "Enabled=true,AttributeName=ttl" \
  --region "$AWS_REGION"
```

## Step 4: Create IAM role and policy for Lambda

```bash
# Create IAM role for Lambda
aws iam create-role \
  --role-name "guardian_lambda_role" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# Create IAM policy for Lambda
aws iam create-policy \
  --policy-name "guardian_lambda_policy" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:logs:*:*:*"
      },
      {
        "Action": [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:s3:::'"$BUCKET_PREFIX"'/*"
      },
      {
        "Action": [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:dynamodb:'"$AWS_REGION"':*:table/GuardianAnalysisResults"
      }
    ]
  }'

# Get the policy ARN
POLICY_ARN=$(aws iam list-policies --query "Policies[?PolicyName=='guardian_lambda_policy'].Arn" --output text)

# Attach policy to role
aws iam attach-role-policy \
  --role-name "guardian_lambda_role" \
  --policy-arn "$POLICY_ARN"
```

## Step 5: Prepare and deploy Lambda function

```bash
# Create a temporary directory for Lambda package
mkdir -p /tmp/guardian_lambda
cp -r /home/sierra/Desktop/projects/Guardianλ/src/* /tmp/guardian_lambda/

# Install dependencies
pip install -t /tmp/guardian_lambda -r /tmp/guardian_lambda/requirements.txt

# Create zip package
cd /tmp/guardian_lambda
zip -r ../lambda_function.zip .

# Create Lambda function
ROLE_ARN=$(aws iam get-role --role-name guardian_lambda_role --query "Role.Arn" --output text)

aws lambda create-function \
  --function-name "GuardianAnalysis" \
  --runtime "python3.9" \
  --role "$ROLE_ARN" \
  --handler "app.lambda_handler" \
  --zip-file "fileb:///tmp/lambda_function.zip" \
  --timeout 30 \
  --memory-size 1024 \
  --environment "Variables={S3_BUCKET=$BUCKET_PREFIX,DYNAMODB_TABLE=GuardianAnalysisResults}" \
  --region "$AWS_REGION"
```

## Step 6: Create API Gateway

```bash
# Create API Gateway
API_ID=$(aws apigateway create-rest-api \
  --name "GuardianAPI" \
  --description "API for Guardian file and URL analysis" \
  --binary-media-types "*/*" \
  --region "$AWS_REGION" \
  --query "id" --output text)

# Get root resource ID
ROOT_RESOURCE_ID=$(aws apigateway get-resources \
  --rest-api-id "$API_ID" \
  --region "$AWS_REGION" \
  --query "items[0].id" --output text)

# Create 'analyze' resource
ANALYZE_RESOURCE_ID=$(aws apigateway create-resource \
  --rest-api-id "$API_ID" \
  --parent-id "$ROOT_RESOURCE_ID" \
  --path-part "analyze" \
  --region "$AWS_REGION" \
  --query "id" --output text)

# Create 'file' resource
FILE_RESOURCE_ID=$(aws apigateway create-resource \
  --rest-api-id "$API_ID" \
  --parent-id "$ANALYZE_RESOURCE_ID" \
  --path-part "file" \
  --region "$AWS_REGION" \
  --query "id" --output text)

# Create 'url' resource
URL_RESOURCE_ID=$(aws apigateway create-resource \
  --rest-api-id "$API_ID" \
  --parent-id "$ANALYZE_RESOURCE_ID" \
  --path-part "url" \
  --region "$AWS_REGION" \
  --query "id" --output text)

# Create POST method for file analysis
aws apigateway put-method \
  --rest-api-id "$API_ID" \
  --resource-id "$FILE_RESOURCE_ID" \
  --http-method "POST" \
  --authorization-type "NONE" \
  --region "$AWS_REGION"

# Create POST method for URL analysis
aws apigateway put-method \
  --rest-api-id "$API_ID" \
  --resource-id "$URL_RESOURCE_ID" \
  --http-method "POST" \
  --authorization-type "NONE" \
  --region "$AWS_REGION"

# Get Lambda function ARN
LAMBDA_ARN=$(aws lambda get-function \
  --function-name "GuardianAnalysis" \
  --query "Configuration.FunctionArn" \
  --output text \
  --region "$AWS_REGION")

# Create integration for file analysis
aws apigateway put-integration \
  --rest-api-id "$API_ID" \
  --resource-id "$FILE_RESOURCE_ID" \
  --http-method "POST" \
  --type "AWS_PROXY" \
  --integration-http-method "POST" \
  --uri "arn:aws:apigateway:$AWS_REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region "$AWS_REGION"

# Create integration for URL analysis
aws apigateway put-integration \
  --rest-api-id "$API_ID" \
  --resource-id "$URL_RESOURCE_ID" \
  --http-method "POST" \
  --type "AWS_PROXY" \
  --integration-http-method "POST" \
  --uri "arn:aws:apigateway:$AWS_REGION:lambda:path/2015-03-31/functions/$LAMBDA_ARN/invocations" \
  --region "$AWS_REGION"

# Add Lambda permissions for API Gateway
aws lambda add-permission \
  --function-name "GuardianAnalysis" \
  --statement-id "AllowExecutionFromAPIGatewayFile" \
  --action "lambda:InvokeFunction" \
  --principal "apigateway.amazonaws.com" \
  --source-arn "arn:aws:execute-api:$AWS_REGION:$(aws sts get-caller-identity --query Account --output text):$API_ID/*/POST/analyze/file" \
  --region "$AWS_REGION"

aws lambda add-permission \
  --function-name "GuardianAnalysis" \
  --statement-id "AllowExecutionFromAPIGatewayUrl" \
  --action "lambda:InvokeFunction" \
  --principal "apigateway.amazonaws.com" \
  --source-arn "arn:aws:execute-api:$AWS_REGION:$(aws sts get-caller-identity --query Account --output text):$API_ID/*/POST/analyze/url" \
  --region "$AWS_REGION"

# Setup CORS for file endpoint
aws apigateway put-method \
  --rest-api-id "$API_ID" \
  --resource-id "$FILE_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --authorization-type "NONE" \
  --region "$AWS_REGION"

aws apigateway put-integration \
  --rest-api-id "$API_ID" \
  --resource-id "$FILE_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --type "MOCK" \
  --request-templates '{"application/json":"{\"statusCode\": 200}"}' \
  --region "$AWS_REGION"

aws apigateway put-method-response \
  --rest-api-id "$API_ID" \
  --resource-id "$FILE_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --status-code "200" \
  --response-parameters "method.response.header.Access-Control-Allow-Origin=true,method.response.header.Access-Control-Allow-Methods=true,method.response.header.Access-Control-Allow-Headers=true" \
  --region "$AWS_REGION"

aws apigateway put-integration-response \
  --rest-api-id "$API_ID" \
  --resource-id "$FILE_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --status-code "200" \
  --response-parameters '{
      "method.response.header.Access-Control-Allow-Origin": "'\''*'\''",
      "method.response.header.Access-Control-Allow-Methods": "'\''POST,OPTIONS'\''",
      "method.response.header.Access-Control-Allow-Headers": "'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key'\''"
    }' \
  --region "$AWS_REGION"

# Setup CORS for URL endpoint
aws apigateway put-method \
  --rest-api-id "$API_ID" \
  --resource-id "$URL_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --authorization-type "NONE" \
  --region "$AWS_REGION"

aws apigateway put-integration \
  --rest-api-id "$API_ID" \
  --resource-id "$URL_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --type "MOCK" \
  --request-templates '{"application/json":"{\"statusCode\": 200}"}' \
  --region "$AWS_REGION"

aws apigateway put-method-response \
  --rest-api-id "$API_ID" \
  --resource-id "$URL_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --status-code "200" \
  --response-parameters "method.response.header.Access-Control-Allow-Origin=true,method.response.header.Access-Control-Allow-Methods=true,method.response.header.Access-Control-Allow-Headers=true" \
  --region "$AWS_REGION"

aws apigateway put-integration-response \
  --rest-api-id "$API_ID" \
  --resource-id "$URL_RESOURCE_ID" \
  --http-method "OPTIONS" \
  --status-code "200" \
  --response-parameters '{
      "method.response.header.Access-Control-Allow-Origin": "'\''*'\''",
      "method.response.header.Access-Control-Allow-Methods": "'\''POST,OPTIONS'\''",
      "method.response.header.Access-Control-Allow-Headers": "'\''Content-Type,X-Amz-Date,Authorization,X-Api-Key'\''"
    }' \
  --region "$AWS_REGION"

# Deploy API
aws apigateway create-deployment \
  --rest-api-id "$API_ID" \
  --stage-name "prod" \
  --region "$AWS_REGION"
```

## Step 7: Create S3 bucket for Web UI

```bash
# Create web UI bucket
aws s3api create-bucket \
  --bucket "$WEB_UI_BUCKET_PREFIX" \
  --region "$AWS_REGION"

# Configure for website hosting
aws s3 website \
  "s3://$WEB_UI_BUCKET_PREFIX" \
  --index-document index.html \
  --error-document index.html

# Set bucket policy for public read access
aws s3api put-bucket-policy \
  --bucket "$WEB_UI_BUCKET_PREFIX" \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "PublicReadGetObject",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::'"$WEB_UI_BUCKET_PREFIX"'/*"
      }
    ]
  }'

# Set bucket ownership controls
aws s3api put-bucket-ownership-controls \
  --bucket "$WEB_UI_BUCKET_PREFIX" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerPreferred}]'

# Disable block public access settings for the website bucket
aws s3api put-public-access-block \
  --bucket "$WEB_UI_BUCKET_PREFIX" \
  --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
```

## Step 8: Deploy Web UI files

```bash
# Check if frontend directory exists
if [ -d "/home/sierra/Desktop/projects/Guardianλ/frontend" ]; then
  # Get API Gateway endpoint and store it as a secret in AWS Secrets Manager
  API_ENDPOINT="https://$API_ID.execute-api.$AWS_REGION.amazonaws.com/prod"
  
  # Create a secret in AWS Secrets Manager
  SECRET_ARN=$(aws secretsmanager create-secret \
    --name "GuardianAPI-Endpoint" \
    --description "Guardian API Endpoint URL" \
    --secret-string "{\"apiEndpoint\":\"$API_ENDPOINT\"}" \
    --region "$AWS_REGION" \
    --query "ARN" --output text)
  
  echo "API Endpoint stored securely in AWS Secrets Manager with ARN: $SECRET_ARN"
  
  # Create a temporary directory for the frontend files
  mkdir -p /tmp/guardian_frontend
  cp -r /home/sierra/Desktop/projects/Guardianλ/frontend/* /tmp/guardian_frontend/
  
  # Update the frontend configuration to use AWS Secrets Manager
  # Note: This assumes there's a config.js file in the frontend. Adjust as needed.
  if [ -f "/tmp/guardian_frontend/src/scripts/config.js" ]; then
    # Replace direct API endpoint with code to fetch from Secrets Manager
    cat > /tmp/guardian_frontend/src/scripts/config.js << EOF
// Guardian API Configuration
// The API endpoint is stored in AWS Secrets Manager for security
const secretName = 'GuardianAPI-Endpoint';
let API_ENDPOINT = '';

// Function to fetch the API endpoint from AWS Secrets Manager
async function fetchApiEndpoint() {
  try {
    // This requires AWS SDK for JavaScript in the browser
    // Make sure to include the AWS SDK in your HTML
    const secretsManager = new AWS.SecretsManager({ region: '$AWS_REGION' });
    const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
    if ('SecretString' in data) {
      const secret = JSON.parse(data.SecretString);
      API_ENDPOINT = secret.apiEndpoint;
      console.log('API endpoint loaded successfully');
    }
  } catch (err) {
    console.error('Error loading API endpoint:', err);
  }
}

// Initialize by fetching the API endpoint
fetchApiEndpoint();
EOF
  fi
  
  # Upload frontend files to S3
  aws s3 sync /tmp/guardian_frontend/ "s3://$WEB_UI_BUCKET_PREFIX/" --acl public-read
  
  # Create IAM policy for the web UI to access the secret
  WEB_UI_POLICY_ARN=$(aws iam create-policy \
    --policy-name "guardian_web_ui_policy" \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "secretsmanager:GetSecretValue",
          "Resource": "'"$SECRET_ARN"'"
        }
      ]
    }' \
    --query "Policy.Arn" --output text)
  
  echo "Web UI deployed to: http://$WEB_UI_BUCKET_PREFIX.s3-website-$AWS_REGION.amazonaws.com"
  echo "Web UI policy created with ARN: $WEB_UI_POLICY_ARN"
else
  echo "Frontend directory not found. Skipping Web UI deployment."
fi
```

## Step 9: Create CloudFront distribution (optional)

```bash
# Create CloudFront distribution
DISTRIBUTION_ID=$(aws cloudfront create-distribution \
  --origin-domain-name "$WEB_UI_BUCKET_PREFIX.s3-website-$AWS_REGION.amazonaws.com" \
  --default-root-object "index.html" \
  --query "Distribution.Id" \
  --output text)

echo "CloudFront distribution created with ID: $DISTRIBUTION_ID"
echo "Wait for the distribution to deploy (can take 15-30 minutes)"
```

## Step 10: Output resource information

```bash
echo "Guardianλ Deployment Complete!"
echo "==============================="
echo "S3 Analysis Bucket: $BUCKET_PREFIX"
echo "DynamoDB Table: GuardianAnalysisResults"
echo "Lambda Function: GuardianAnalysis"
echo "API Gateway ID: $API_ID (endpoint stored in AWS Secrets Manager)"
echo "API Secret ARN: $SECRET_ARN"
echo "Web UI URL: http://$WEB_UI_BUCKET_PREFIX.s3-website-$AWS_REGION.amazonaws.com"
if [ -n "$DISTRIBUTION_ID" ]; then
  echo "CloudFront Distribution ID: $DISTRIBUTION_ID"
fi
echo "==============================="
echo "API Usage (using the endpoint from Secrets Manager):"
echo "POST /analyze/file - For file analysis"
echo "POST /analyze/url - For URL analysis"
```

## Testing the Deployment

### Retrieve the API endpoint securely:

```bash
# Retrieve the API endpoint from Secrets Manager
API_ENDPOINT=$(aws secretsmanager get-secret-value \
  --secret-id "GuardianAPI-Endpoint" \
  --query "SecretString" \
  --output text | jq -r '.apiEndpoint')
```

### Test URL Analysis:

```bash
curl -X POST \
  "$API_ENDPOINT/analyze/url" \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://www.example.com"}'
```

### Test File Analysis:

```bash
curl -X POST \
  "$API_ENDPOINT/analyze/file" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary '@/path/to/test/file.txt'
```
