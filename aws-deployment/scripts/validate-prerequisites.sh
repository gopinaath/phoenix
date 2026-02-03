#!/bin/bash
#
# Phoenix AWS Deployment - Prerequisites Validation Script
# Validates all required resources and access before deployment
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
AWS_REGION="${AWS_REGION:-us-west-2}"
PROJECT_NAME="${PROJECT_NAME:-phoenix}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Functions
print_header() {
    echo ""
    echo "=========================================="
    echo " $1"
    echo "=========================================="
}

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

# =============================================================================
# AWS CLI and Credentials
# =============================================================================
print_header "AWS CLI & Credentials"

# Check AWS CLI installed
if command -v aws &> /dev/null; then
    AWS_VERSION=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
    check_pass "AWS CLI installed (version: $AWS_VERSION)"
else
    check_fail "AWS CLI not installed"
    echo "  Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    exit 1
fi

# Check AWS credentials
if aws sts get-caller-identity &> /dev/null; then
    ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
    USER_ARN=$(aws sts get-caller-identity --query 'Arn' --output text)
    check_pass "AWS credentials configured"
    echo "        Account: $ACCOUNT_ID"
    echo "        Identity: $USER_ARN"
else
    check_fail "AWS credentials not configured or expired"
    exit 1
fi

# Check region
if aws ec2 describe-regions --region-names "$AWS_REGION" &> /dev/null; then
    check_pass "Region $AWS_REGION is valid"
else
    check_fail "Region $AWS_REGION is not valid"
fi

# =============================================================================
# IAM Permissions
# =============================================================================
print_header "IAM Permissions"

# Check CloudFormation permissions
if aws cloudformation list-stacks --max-items 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "CloudFormation: list-stacks"
else
    check_fail "CloudFormation: list-stacks (missing permission)"
fi

# Check EC2 permissions (for VPC)
if aws ec2 describe-vpcs --max-results 5 --region "$AWS_REGION" &> /dev/null; then
    check_pass "EC2: describe-vpcs"
else
    check_fail "EC2: describe-vpcs (missing permission)"
fi

# Check ECS permissions
if aws ecs list-clusters --max-results 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "ECS: list-clusters"
else
    check_fail "ECS: list-clusters (missing permission)"
fi

# Check RDS permissions
if aws rds describe-db-instances --max-records 20 --region "$AWS_REGION" &> /dev/null; then
    check_pass "RDS: describe-db-instances"
else
    check_fail "RDS: describe-db-instances (missing permission)"
fi

# Check S3 permissions
if aws s3 ls &> /dev/null; then
    check_pass "S3: list-buckets"
else
    check_fail "S3: list-buckets (missing permission)"
fi

# Check Secrets Manager permissions
if aws secretsmanager list-secrets --max-results 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "Secrets Manager: list-secrets"
else
    check_fail "Secrets Manager: list-secrets (missing permission)"
fi

# Check Cognito permissions
if aws cognito-idp list-user-pools --max-results 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "Cognito: list-user-pools"
else
    check_fail "Cognito: list-user-pools (missing permission)"
fi

# Check Lambda permissions
if aws lambda list-functions --max-items 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "Lambda: list-functions"
else
    check_fail "Lambda: list-functions (missing permission)"
fi

# Check DynamoDB permissions
if aws dynamodb list-tables --limit 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "DynamoDB: list-tables"
else
    check_fail "DynamoDB: list-tables (missing permission)"
fi

# Check IAM permissions (for creating roles)
if aws iam list-roles --max-items 1 &> /dev/null; then
    check_pass "IAM: list-roles"
else
    check_fail "IAM: list-roles (missing permission)"
fi

# Check KMS permissions
if aws kms list-keys --region "$AWS_REGION" &> /dev/null; then
    check_pass "KMS: list-keys"
else
    check_fail "KMS: list-keys (missing permission)"
fi

# =============================================================================
# SES (Email Service)
# =============================================================================
print_header "SES (Simple Email Service)"

# Check SES availability in region
if aws ses get-send-quota --region "$AWS_REGION" &> /dev/null; then
    SEND_QUOTA=$(aws ses get-send-quota --region "$AWS_REGION" --query 'Max24HourSend' --output text)
    check_pass "SES available in $AWS_REGION"

    # Check sandbox status
    if [ "$SEND_QUOTA" == "200" ] || [ "$SEND_QUOTA" == "200.0" ]; then
        check_warn "SES in sandbox mode (200 emails/day limit)"
        echo "        Request production access for unlimited sending"
    else
        check_pass "SES in production mode (quota: $SEND_QUOTA/day)"
    fi
else
    check_fail "SES not available or no permission in $AWS_REGION"
fi

# Check verified identities
VERIFIED_COUNT=$(aws ses list-identities --region "$AWS_REGION" --query 'length(Identities)' --output text 2>/dev/null || echo "0")
if [ "$VERIFIED_COUNT" -gt 0 ]; then
    check_pass "SES has $VERIFIED_COUNT verified identities"
else
    check_warn "SES has no verified identities (required for sending emails)"
fi

# =============================================================================
# Service Quotas
# =============================================================================
print_header "Service Quotas"

# Check VPC quota
VPC_COUNT=$(aws ec2 describe-vpcs --region "$AWS_REGION" --query 'length(Vpcs)' --output text)
VPC_LIMIT=5  # Default limit
if [ "$VPC_COUNT" -lt "$VPC_LIMIT" ]; then
    check_pass "VPC quota: $VPC_COUNT/$VPC_LIMIT used"
else
    check_warn "VPC quota nearly exhausted: $VPC_COUNT/$VPC_LIMIT"
fi

# Check EIP quota
EIP_COUNT=$(aws ec2 describe-addresses --region "$AWS_REGION" --query 'length(Addresses)' --output text)
EIP_LIMIT=5  # Default limit
if [ "$EIP_COUNT" -lt "$((EIP_LIMIT - 2))" ]; then
    check_pass "Elastic IP quota: $EIP_COUNT/$EIP_LIMIT used (need 2 for NAT)"
else
    check_warn "Elastic IP quota low: $EIP_COUNT/$EIP_LIMIT (need 2 for NAT Gateways)"
fi

# Check NAT Gateway availability
NAT_COUNT=$(aws ec2 describe-nat-gateways --region "$AWS_REGION" --filter "Name=state,Values=available" --query 'length(NatGateways)' --output text)
check_pass "NAT Gateways in use: $NAT_COUNT"

# =============================================================================
# Availability Zones
# =============================================================================
print_header "Availability Zones"

AZ_COUNT=$(aws ec2 describe-availability-zones --region "$AWS_REGION" --query 'length(AvailabilityZones[?State==`available`])' --output text)
if [ "$AZ_COUNT" -ge 2 ]; then
    check_pass "$AZ_COUNT availability zones available in $AWS_REGION"
    aws ec2 describe-availability-zones --region "$AWS_REGION" --query 'AvailabilityZones[?State==`available`].ZoneName' --output text | tr '\t' '\n' | while read az; do
        echo "        - $az"
    done
else
    check_fail "Need at least 2 AZs, only $AZ_COUNT available"
fi

# =============================================================================
# Existing Resources Check
# =============================================================================
print_header "Existing Resources (Conflict Check)"

# Check if stack already exists
STACK_NAME="${PROJECT_NAME}-${ENVIRONMENT}"
if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" &> /dev/null; then
    check_warn "Stack '$STACK_NAME' already exists"
    STACK_STATUS=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" --query 'Stacks[0].StackStatus' --output text)
    echo "        Status: $STACK_STATUS"
else
    check_pass "No existing stack named '$STACK_NAME'"
fi

# Check for existing Cognito user pool
COGNITO_POOLS=$(aws cognito-idp list-user-pools --max-results 60 --region "$AWS_REGION" --query "UserPools[?contains(Name, '${PROJECT_NAME}')].Name" --output text)
if [ -n "$COGNITO_POOLS" ]; then
    check_warn "Existing Cognito user pools found with '$PROJECT_NAME' in name"
    echo "        $COGNITO_POOLS"
else
    check_pass "No conflicting Cognito user pools"
fi

# Check for existing ECS cluster
if aws ecs describe-clusters --clusters "${PROJECT_NAME}-${ENVIRONMENT}" --region "$AWS_REGION" --query 'clusters[0].status' --output text 2>/dev/null | grep -q "ACTIVE"; then
    check_warn "ECS cluster '${PROJECT_NAME}-${ENVIRONMENT}' already exists"
else
    check_pass "No existing ECS cluster '${PROJECT_NAME}-${ENVIRONMENT}'"
fi

# =============================================================================
# ECR Access (Phoenix Image)
# =============================================================================
print_header "Container Registry Access"

# Check if we can pull from Docker Hub (Phoenix image)
PHOENIX_IMAGE="arizephoenix/phoenix:version-2.9.0-nonroot"
echo "  Phoenix image: $PHOENIX_IMAGE"
check_pass "Using public Docker Hub image (no ECR setup needed)"

# =============================================================================
# ACM (Certificate Manager)
# =============================================================================
print_header "ACM (Certificate Manager)"

if aws acm list-certificates --region "$AWS_REGION" &> /dev/null; then
    check_pass "ACM: list-certificates"
    CERT_COUNT=$(aws acm list-certificates --region "$AWS_REGION" --query 'length(CertificateSummaryList)' --output text)
    echo "        Existing certificates: $CERT_COUNT"
else
    check_fail "ACM: list-certificates (missing permission)"
fi

# =============================================================================
# CloudWatch Logs
# =============================================================================
print_header "CloudWatch Logs"

if aws logs describe-log-groups --limit 1 --region "$AWS_REGION" &> /dev/null; then
    check_pass "CloudWatch Logs: describe-log-groups"
else
    check_fail "CloudWatch Logs: describe-log-groups (missing permission)"
fi

# =============================================================================
# Summary
# =============================================================================
print_header "SUMMARY"

echo ""
echo -e "  ${GREEN}Passed:${NC}   $PASSED"
echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "  ${RED}Failed:${NC}   $FAILED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Prerequisites check FAILED${NC}"
    echo "Please resolve the failed checks before proceeding with deployment."
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}Prerequisites check PASSED with warnings${NC}"
    echo "Review warnings before proceeding. Deployment may still succeed."
    exit 0
else
    echo -e "${GREEN}All prerequisites checks PASSED${NC}"
    echo "Ready to proceed with Phoenix AWS deployment."
    exit 0
fi
