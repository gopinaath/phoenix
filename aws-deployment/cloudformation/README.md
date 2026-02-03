# Phoenix AWS CloudFormation Deployment

Production-ready CloudFormation templates for deploying Phoenix on AWS.

## Architecture

```
Internet -> WAF -> ALB -> ECS Fargate (Phoenix) -> RDS PostgreSQL
                    |
                    +-> Cognito (OAuth2 Authentication)
```

## Templates

| Template | Description |
|----------|-------------|
| `main.yaml` | Parent stack orchestrating all nested stacks |
| `network.yaml` | VPC, subnets, NAT gateways, VPC endpoints |
| `security.yaml` | Security groups, IAM roles, KMS, Cognito |
| `database.yaml` | RDS PostgreSQL Multi-AZ |
| `compute.yaml` | ECS Fargate, ALB, auto-scaling |

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. S3 bucket for template storage
3. Route53 hosted zone (for DNS)
4. Customize `AllowedEmailDomains` parameter in security stack

## Deployment

### 1. Create S3 bucket for templates

```bash
STACK_NAME=phoenix-production
AWS_REGION=us-west-2

aws s3 mb s3://${STACK_NAME}-templates --region ${AWS_REGION}
```

### 2. Upload nested templates

```bash
aws s3 cp network.yaml s3://${STACK_NAME}-templates/
aws s3 cp security.yaml s3://${STACK_NAME}-templates/
aws s3 cp database.yaml s3://${STACK_NAME}-templates/
aws s3 cp compute.yaml s3://${STACK_NAME}-templates/
```

### 3. Deploy the main stack

```bash
aws cloudformation create-stack \
  --stack-name ${STACK_NAME} \
  --template-body file://main.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=production \
    ParameterKey=ProjectName,ParameterValue=phoenix \
    ParameterKey=AvailabilityZones,ParameterValue="us-west-2a,us-west-2b" \
    ParameterKey=DBInstanceClass,ParameterValue=db.t3.medium \
    ParameterKey=DBAllocatedStorage,ParameterValue=100 \
    ParameterKey=DesiredCount,ParameterValue=2 \
    ParameterKey=TaskCpu,ParameterValue=1024 \
    ParameterKey=TaskMemory,ParameterValue=2048 \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${AWS_REGION}
```

### 4. Complete ACM certificate validation

After deployment starts, validate the ACM certificate via DNS:

```bash
# Get the certificate ARN
CERT_ARN=$(aws cloudformation describe-stack-resources \
  --stack-name ${STACK_NAME}-compute \
  --logical-resource-id ACMCertificate \
  --query 'StackResources[0].PhysicalResourceId' \
  --output text)

# Get DNS validation records
aws acm describe-certificate \
  --certificate-arn ${CERT_ARN} \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord'
```

Add the CNAME record to your DNS to validate the certificate.

### 5. Configure DNS

After deployment completes, create a DNS record pointing to the ALB:

```bash
# Get ALB DNS name
ALB_DNS=$(aws cloudformation describe-stacks \
  --stack-name ${STACK_NAME} \
  --query 'Stacks[0].Outputs[?OutputKey==`PhoenixURL`].OutputValue' \
  --output text)

echo "Create DNS CNAME: phoenix.production.example.com -> ${ALB_DNS}"
```

## Configuration

### Email Domain Allow-list (Cognito)

To restrict sign-ups to specific email domains, update the `AllowedEmailDomains` parameter in `security.yaml`:

```yaml
AllowedEmailDomains:
  Type: CommaDelimitedList
  Default: 'yourcompany.com,partner.com'
```

### Instance Sizing

| Environment | DB Instance | ECS Tasks | Monthly Cost |
|-------------|-------------|-----------|--------------|
| Development | db.t3.medium | 1-2 | ~$175-400 |
| Production | db.r6g.large | 2-6 | ~$600-1,200 |
| Enterprise | db.r6g.xlarge | 4-10 | ~$2,000-5,000 |

## Security Features

- VPC with private subnets for compute and data tiers
- VPC endpoints for AWS services (no internet egress required)
- TLS 1.3 enforced on ALB
- RDS encryption at rest with KMS
- Secrets Manager for all credentials
- Cognito with email domain allow-list
- CloudWatch logging and alarms

## Monitoring

The stack creates CloudWatch alarms for:

- ECS CPU/Memory utilization
- RDS CPU/Storage/Connections
- ALB 5xx errors
- Target response time

## Updates

To update the stack:

```bash
aws cloudformation update-stack \
  --stack-name ${STACK_NAME} \
  --template-body file://main.yaml \
  --parameters \
    ParameterKey=Environment,UsePreviousValue=true \
    ParameterKey=ProjectName,UsePreviousValue=true \
    ParameterKey=AvailabilityZones,UsePreviousValue=true \
    ParameterKey=DBInstanceClass,UsePreviousValue=true \
    ParameterKey=DBAllocatedStorage,UsePreviousValue=true \
    ParameterKey=DesiredCount,ParameterValue=4 \
    ParameterKey=TaskCpu,UsePreviousValue=true \
    ParameterKey=TaskMemory,UsePreviousValue=true \
  --capabilities CAPABILITY_NAMED_IAM
```

## Cleanup

To delete all resources:

```bash
# Delete the main stack (this deletes all nested stacks)
aws cloudformation delete-stack --stack-name ${STACK_NAME}

# Wait for deletion
aws cloudformation wait stack-delete-complete --stack-name ${STACK_NAME}

# Delete the S3 bucket
aws s3 rb s3://${STACK_NAME}-templates --force
```

Note: RDS has deletion protection enabled. Disable it first if you want to delete the database.

## Troubleshooting

### Certificate validation timeout

ACM certificates require DNS validation. If the stack hangs on certificate creation:

1. Check CloudFormation events for the certificate ARN
2. Retrieve validation CNAME record from ACM console
3. Add the record to your DNS
4. Certificate validates automatically

### ECS service fails to start

Check CloudWatch logs:

```bash
aws logs tail /ecs/phoenix-production --follow
```

### Database connection issues

Verify the secret was created correctly:

```bash
aws secretsmanager get-secret-value \
  --secret-id phoenix/database-url \
  --query SecretString \
  --output text
```
