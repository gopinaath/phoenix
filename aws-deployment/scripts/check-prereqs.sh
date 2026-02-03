#!/bin/bash
# Quick prerequisites check for Phoenix AWS deployment

AWS_REGION="${AWS_REGION:-us-west-2}"
echo "=== Phoenix AWS Prerequisites Check ==="
echo "Region: $AWS_REGION"
echo ""

# Check AWS identity
echo "1. AWS Identity:"
aws sts get-caller-identity --output table || { echo "FAILED: AWS credentials"; exit 1; }

# Check key permissions
echo ""
echo "2. Service Permissions:"
services=(
    "cloudformation:aws cloudformation list-stacks --max-items 1"
    "ec2:aws ec2 describe-vpcs --max-results 5"
    "ecs:aws ecs list-clusters --max-results 1"
    "rds:aws rds describe-db-instances --max-records 20"
    "s3:aws s3 ls"
    "cognito:aws cognito-idp list-user-pools --max-results 1"
    "lambda:aws lambda list-functions --max-items 1"
    "dynamodb:aws dynamodb list-tables --limit 1"
    "iam:aws iam list-roles --max-items 1"
    "ses:aws ses get-send-quota"
    "acm:aws acm list-certificates"
    "logs:aws logs describe-log-groups --limit 1"
    "kms:aws kms list-keys"
    "secretsmanager:aws secretsmanager list-secrets --max-results 1"
)

for svc in "${services[@]}"; do
    name="${svc%%:*}"
    cmd="${svc#*:}"
    if eval "$cmd --region $AWS_REGION" > /dev/null 2>&1; then
        echo "  [OK] $name"
    else
        echo "  [FAIL] $name"
    fi
done

# Check quotas
echo ""
echo "3. Resource Quotas:"
vpc_count=$(aws ec2 describe-vpcs --region $AWS_REGION --query 'length(Vpcs)' --output text)
eip_count=$(aws ec2 describe-addresses --region $AWS_REGION --query 'length(Addresses)' --output text)
az_count=$(aws ec2 describe-availability-zones --region $AWS_REGION --query 'length(AvailabilityZones[?State==`available`])' --output text)
echo "  VPCs: $vpc_count/5"
echo "  Elastic IPs: $eip_count/5 (need 2 for NAT)"
echo "  Availability Zones: $az_count"

# SES status
echo ""
echo "4. SES Status:"
ses_quota=$(aws ses get-send-quota --region $AWS_REGION --query 'Max24HourSend' --output text 2>/dev/null || echo "N/A")
if [ "$ses_quota" = "200" ] || [ "$ses_quota" = "200.0" ]; then
    echo "  Mode: Sandbox (200/day limit) - OK for testing"
else
    echo "  Mode: Production (quota: $ses_quota/day)"
fi

echo ""
echo "=== Prerequisites check complete ==="
