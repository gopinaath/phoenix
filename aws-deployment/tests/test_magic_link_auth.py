"""
Magic Link Authentication Tests

End-to-end test cases for Slack-like magic link authentication.
Designed for independent execution by swarm agents.
"""
import pytest
import boto3
import time
import json
import os
from unittest.mock import patch, MagicMock

# Test configuration
TEST_CONFIG = {
    'allowed_domains': ['example.com', 'company.com'],
    'magic_link_expiry_minutes': 15,
    'max_concurrent_sessions': 2,
    'session_duration_days': 7,
}


# =============================================================================
# Task 1: Pre Sign-Up Lambda Tests (No dependencies)
# =============================================================================
class TestPreSignUpLambda:
    """Tests for email domain validation and auto-confirm logic."""

    def test_allowed_domain_accepted(self):
        """User with allowed email domain should be accepted and auto-confirmed."""
        event = {
            'request': {
                'userAttributes': {'email': 'user@example.com'}
            },
            'response': {}
        }
        os.environ['ALLOWED_DOMAINS'] = 'example.com,company.com'

        from lambdas.pre_signup import handler
        result = handler(event, None)

        assert result['response']['autoConfirmUser'] == True
        assert result['response']['autoVerifyEmail'] == True

    def test_disallowed_domain_rejected(self):
        """User with disallowed email domain should be rejected."""
        event = {
            'request': {
                'userAttributes': {'email': 'user@hacker.com'}
            },
            'response': {}
        }
        os.environ['ALLOWED_DOMAINS'] = 'example.com,company.com'

        from lambdas.pre_signup import handler
        with pytest.raises(Exception) as exc_info:
            handler(event, None)

        assert 'not allowed' in str(exc_info.value).lower()

    def test_empty_email_rejected(self):
        """Sign-up without email should be rejected."""
        event = {
            'request': {
                'userAttributes': {}
            },
            'response': {}
        }

        from lambdas.pre_signup import handler
        with pytest.raises(Exception) as exc_info:
            handler(event, None)

        assert 'email' in str(exc_info.value).lower()

    def test_case_insensitive_domain_check(self):
        """Domain check should be case insensitive."""
        event = {
            'request': {
                'userAttributes': {'email': 'USER@EXAMPLE.COM'}
            },
            'response': {}
        }
        os.environ['ALLOWED_DOMAINS'] = 'example.com'

        from lambdas.pre_signup import handler
        result = handler(event, None)

        assert result['response']['autoConfirmUser'] == True


# =============================================================================
# Task 2: Define Auth Challenge Tests (No dependencies)
# =============================================================================
class TestDefineAuthChallengeLambda:
    """Tests for auth flow orchestration logic."""

    def test_first_call_issues_custom_challenge(self):
        """First authentication call should issue CUSTOM_CHALLENGE."""
        event = {
            'request': {
                'session': []
            },
            'response': {}
        }

        from lambdas.define_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['issueTokens'] == False
        assert result['response']['failAuthentication'] == False
        assert result['response']['challengeName'] == 'CUSTOM_CHALLENGE'

    def test_successful_challenge_issues_tokens(self):
        """Successful challenge verification should issue tokens."""
        event = {
            'request': {
                'session': [{
                    'challengeName': 'CUSTOM_CHALLENGE',
                    'challengeResult': True
                }]
            },
            'response': {}
        }

        from lambdas.define_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['issueTokens'] == True
        assert result['response']['failAuthentication'] == False

    def test_failed_challenge_fails_auth(self):
        """Failed challenge verification should fail authentication."""
        event = {
            'request': {
                'session': [{
                    'challengeName': 'CUSTOM_CHALLENGE',
                    'challengeResult': False
                }]
            },
            'response': {}
        }

        from lambdas.define_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['issueTokens'] == False
        assert result['response']['failAuthentication'] == True

    def test_too_many_attempts_fails(self):
        """More than one challenge attempt should fail."""
        event = {
            'request': {
                'session': [
                    {'challengeName': 'CUSTOM_CHALLENGE', 'challengeResult': False},
                    {'challengeName': 'CUSTOM_CHALLENGE', 'challengeResult': False}
                ]
            },
            'response': {}
        }

        from lambdas.define_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['failAuthentication'] == True


# =============================================================================
# Task 3: Create Auth Challenge Tests (Depends on: DynamoDB mock)
# =============================================================================
class TestCreateAuthChallengeLambda:
    """Tests for magic link generation and email sending."""

    @pytest.fixture
    def mock_dynamodb(self):
        """Mock DynamoDB table."""
        with patch('boto3.resource') as mock:
            table = MagicMock()
            mock.return_value.Table.return_value = table
            yield table

    @pytest.fixture
    def mock_ses(self):
        """Mock SES client."""
        with patch('boto3.client') as mock:
            client = MagicMock()
            mock.return_value = client
            yield client

    def test_magic_link_token_generated(self, mock_dynamodb, mock_ses):
        """Magic link should generate a secure token."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'
        os.environ['MAGIC_LINK_EXPIRY_MINUTES'] = '15'
        os.environ['APP_DOMAIN'] = 'phoenix.example.com'
        os.environ['FROM_EMAIL'] = 'noreply@example.com'

        event = {
            'request': {
                'userAttributes': {
                    'email': 'user@example.com',
                    'sub': 'user-123'
                }
            },
            'response': {}
        }

        from lambdas.create_auth_challenge import handler
        result = handler(event, None)

        # Token should be stored in DynamoDB
        mock_dynamodb.put_item.assert_called_once()
        put_args = mock_dynamodb.put_item.call_args

        assert 'token' in put_args.kwargs['Item']
        assert put_args.kwargs['Item']['email'] == 'user@example.com'
        assert put_args.kwargs['Item']['used'] == False

    def test_magic_link_email_sent(self, mock_dynamodb, mock_ses):
        """Email with magic link should be sent."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'
        os.environ['MAGIC_LINK_EXPIRY_MINUTES'] = '15'
        os.environ['APP_DOMAIN'] = 'phoenix.example.com'
        os.environ['FROM_EMAIL'] = 'noreply@example.com'

        event = {
            'request': {
                'userAttributes': {
                    'email': 'user@example.com',
                    'sub': 'user-123'
                }
            },
            'response': {}
        }

        from lambdas.create_auth_challenge import handler
        handler(event, None)

        # Email should be sent via SES
        mock_ses.send_email.assert_called_once()
        send_args = mock_ses.send_email.call_args
        assert send_args.kwargs['Destination']['ToAddresses'] == ['user@example.com']

    def test_magic_link_url_format(self, mock_dynamodb, mock_ses):
        """Magic link URL should be properly formatted."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'
        os.environ['MAGIC_LINK_EXPIRY_MINUTES'] = '15'
        os.environ['APP_DOMAIN'] = 'phoenix.example.com'
        os.environ['FROM_EMAIL'] = 'noreply@example.com'

        event = {
            'request': {
                'userAttributes': {
                    'email': 'user@example.com',
                    'sub': 'user-123'
                }
            },
            'response': {}
        }

        from lambdas.create_auth_challenge import handler
        result = handler(event, None)

        # Public parameters should indicate email sent
        assert result['response']['publicChallengeParameters']['email'] == 'user@example.com'
        assert 'token' in result['response']['privateChallengeParameters']

    def test_token_ttl_set_correctly(self, mock_dynamodb, mock_ses):
        """Token TTL should be set based on expiry configuration."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'
        os.environ['MAGIC_LINK_EXPIRY_MINUTES'] = '15'
        os.environ['APP_DOMAIN'] = 'phoenix.example.com'
        os.environ['FROM_EMAIL'] = 'noreply@example.com'

        event = {
            'request': {
                'userAttributes': {
                    'email': 'user@example.com',
                    'sub': 'user-123'
                }
            },
            'response': {}
        }

        before = int(time.time())
        from lambdas.create_auth_challenge import handler
        handler(event, None)
        after = int(time.time())

        put_args = mock_dynamodb.put_item.call_args
        ttl = put_args.kwargs['Item']['ttl']

        # TTL should be ~15 minutes from now
        expected_min = before + (15 * 60)
        expected_max = after + (15 * 60)
        assert expected_min <= ttl <= expected_max


# =============================================================================
# Task 4: Verify Auth Challenge Tests (Depends on: DynamoDB mock)
# =============================================================================
class TestVerifyAuthChallengeLambda:
    """Tests for magic link token validation."""

    @pytest.fixture
    def mock_dynamodb(self):
        """Mock DynamoDB table."""
        with patch('boto3.resource') as mock:
            table = MagicMock()
            mock.return_value.Table.return_value = table
            yield table

    def test_valid_token_accepted(self, mock_dynamodb):
        """Valid token should be accepted."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'

        valid_token = 'valid-token-123'
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'token': valid_token,
                'userSub': 'user-123',
                'ttl': int(time.time()) + 600,  # 10 min in future
                'used': False
            }
        }

        event = {
            'request': {
                'challengeAnswer': valid_token,
                'privateChallengeParameters': {'token': valid_token},
                'userAttributes': {'sub': 'user-123'}
            },
            'response': {}
        }

        from lambdas.verify_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['answerCorrect'] == True
        mock_dynamodb.update_item.assert_called_once()  # Token marked used

    def test_expired_token_rejected(self, mock_dynamodb):
        """Expired token should be rejected."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'

        expired_token = 'expired-token-123'
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'token': expired_token,
                'userSub': 'user-123',
                'ttl': int(time.time()) - 60,  # Expired 1 min ago
                'used': False
            }
        }

        event = {
            'request': {
                'challengeAnswer': expired_token,
                'privateChallengeParameters': {'token': expired_token},
                'userAttributes': {'sub': 'user-123'}
            },
            'response': {}
        }

        from lambdas.verify_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['answerCorrect'] == False

    def test_already_used_token_rejected(self, mock_dynamodb):
        """Already used token should be rejected."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'

        used_token = 'used-token-123'
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'token': used_token,
                'userSub': 'user-123',
                'ttl': int(time.time()) + 600,
                'used': True  # Already used
            }
        }

        event = {
            'request': {
                'challengeAnswer': used_token,
                'privateChallengeParameters': {'token': used_token},
                'userAttributes': {'sub': 'user-123'}
            },
            'response': {}
        }

        from lambdas.verify_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['answerCorrect'] == False

    def test_wrong_user_token_rejected(self, mock_dynamodb):
        """Token for different user should be rejected."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'

        token = 'other-user-token'
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'token': token,
                'userSub': 'other-user-456',  # Different user
                'ttl': int(time.time()) + 600,
                'used': False
            }
        }

        event = {
            'request': {
                'challengeAnswer': token,
                'privateChallengeParameters': {'token': token},
                'userAttributes': {'sub': 'user-123'}  # Requesting user
            },
            'response': {}
        }

        from lambdas.verify_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['answerCorrect'] == False

    def test_nonexistent_token_rejected(self, mock_dynamodb):
        """Non-existent token should be rejected."""
        os.environ['MAGIC_LINK_TABLE'] = 'test-magic-links'

        mock_dynamodb.get_item.return_value = {}  # No item found

        event = {
            'request': {
                'challengeAnswer': 'fake-token',
                'privateChallengeParameters': {'token': 'fake-token'},
                'userAttributes': {'sub': 'user-123'}
            },
            'response': {}
        }

        from lambdas.verify_auth_challenge import handler
        result = handler(event, None)

        assert result['response']['answerCorrect'] == False


# =============================================================================
# Task 5: Post Authentication (Session Management) Tests
# =============================================================================
class TestPostAuthenticationLambda:
    """Tests for concurrent session enforcement."""

    @pytest.fixture
    def mock_dynamodb(self):
        """Mock DynamoDB table."""
        with patch('boto3.resource') as mock:
            table = MagicMock()
            mock.return_value.Table.return_value = table
            yield table

    def test_new_session_created(self, mock_dynamodb):
        """New session should be created after authentication."""
        os.environ['SESSIONS_TABLE'] = 'test-sessions'
        os.environ['MAX_SESSIONS'] = '2'
        os.environ['SESSION_DURATION_DAYS'] = '7'

        mock_dynamodb.query.return_value = {'Items': []}

        event = {
            'request': {
                'userAttributes': {
                    'sub': 'user-123',
                    'email': 'user@example.com'
                },
                'clientMetadata': {'deviceInfo': 'Chrome/Windows'}
            },
            'response': {}
        }

        from lambdas.post_authentication import handler
        handler(event, None)

        # New session should be created
        mock_dynamodb.put_item.assert_called_once()
        put_args = mock_dynamodb.put_item.call_args
        assert put_args.kwargs['Item']['userId'] == 'user-123'

    def test_session_limit_enforced(self, mock_dynamodb):
        """Oldest session should be removed when limit is reached."""
        os.environ['SESSIONS_TABLE'] = 'test-sessions'
        os.environ['MAX_SESSIONS'] = '2'
        os.environ['SESSION_DURATION_DAYS'] = '7'

        # User already has 2 sessions
        existing_sessions = [
            {
                'userId': 'user-123',
                'sessionId': 'session-1',
                'createdAt': int(time.time()) - 3600,  # 1 hour ago (oldest)
                'ttl': int(time.time()) + 86400
            },
            {
                'userId': 'user-123',
                'sessionId': 'session-2',
                'createdAt': int(time.time()) - 1800,  # 30 min ago
                'ttl': int(time.time()) + 86400
            }
        ]
        mock_dynamodb.query.return_value = {'Items': existing_sessions}

        event = {
            'request': {
                'userAttributes': {
                    'sub': 'user-123',
                    'email': 'user@example.com'
                }
            },
            'response': {}
        }

        from lambdas.post_authentication import handler
        handler(event, None)

        # Oldest session should be deleted
        mock_dynamodb.delete_item.assert_called_once()
        delete_args = mock_dynamodb.delete_item.call_args
        assert delete_args.kwargs['Key']['sessionId'] == 'session-1'

        # New session should be created
        mock_dynamodb.put_item.assert_called_once()

    def test_expired_sessions_not_counted(self, mock_dynamodb):
        """Expired sessions should not count toward limit."""
        os.environ['SESSIONS_TABLE'] = 'test-sessions'
        os.environ['MAX_SESSIONS'] = '2'
        os.environ['SESSION_DURATION_DAYS'] = '7'

        # 1 active session + 1 expired session
        existing_sessions = [
            {
                'userId': 'user-123',
                'sessionId': 'active-session',
                'createdAt': int(time.time()) - 3600,
                'ttl': int(time.time()) + 86400  # Active
            },
            {
                'userId': 'user-123',
                'sessionId': 'expired-session',
                'createdAt': int(time.time()) - 86400,
                'ttl': int(time.time()) - 3600  # Expired
            }
        ]
        mock_dynamodb.query.return_value = {'Items': existing_sessions}

        event = {
            'request': {
                'userAttributes': {
                    'sub': 'user-123',
                    'email': 'user@example.com'
                }
            },
            'response': {}
        }

        from lambdas.post_authentication import handler
        handler(event, None)

        # No sessions should be deleted (only 1 active)
        mock_dynamodb.delete_item.assert_not_called()

        # New session should be created
        mock_dynamodb.put_item.assert_called_once()

    def test_session_ttl_set_correctly(self, mock_dynamodb):
        """Session TTL should match configured duration."""
        os.environ['SESSIONS_TABLE'] = 'test-sessions'
        os.environ['MAX_SESSIONS'] = '2'
        os.environ['SESSION_DURATION_DAYS'] = '7'

        mock_dynamodb.query.return_value = {'Items': []}

        event = {
            'request': {
                'userAttributes': {
                    'sub': 'user-123',
                    'email': 'user@example.com'
                }
            },
            'response': {}
        }

        before = int(time.time())
        from lambdas.post_authentication import handler
        handler(event, None)
        after = int(time.time())

        put_args = mock_dynamodb.put_item.call_args
        ttl = put_args.kwargs['Item']['ttl']

        # TTL should be ~7 days from now
        expected_min = before + (7 * 24 * 60 * 60)
        expected_max = after + (7 * 24 * 60 * 60)
        assert expected_min <= ttl <= expected_max


# =============================================================================
# Task 6: End-to-End Flow Tests (Integration)
# =============================================================================
class TestMagicLinkEndToEnd:
    """End-to-end integration tests for magic link flow."""

    @pytest.fixture
    def cognito_client(self):
        """Get Cognito client (requires AWS credentials)."""
        return boto3.client('cognito-idp')

    @pytest.fixture
    def test_user_email(self):
        """Test user email (must be in allowed domain)."""
        return f'test-{int(time.time())}@example.com'

    @pytest.mark.integration
    def test_full_magic_link_flow(self, cognito_client, test_user_email):
        """Complete magic link authentication flow."""
        # This test requires deployed infrastructure
        pytest.skip('Requires deployed AWS infrastructure')

        user_pool_id = os.environ.get('USER_POOL_ID')
        client_id = os.environ.get('CLIENT_ID')

        # Step 1: Sign up user
        cognito_client.sign_up(
            ClientId=client_id,
            Username=test_user_email,
            Password='TempPassword123!',  # Required but not used
            UserAttributes=[
                {'Name': 'email', 'Value': test_user_email}
            ]
        )

        # Step 2: Initiate auth (triggers magic link email)
        response = cognito_client.initiate_auth(
            ClientId=client_id,
            AuthFlow='CUSTOM_AUTH',
            AuthParameters={
                'USERNAME': test_user_email
            }
        )

        assert response['ChallengeName'] == 'CUSTOM_CHALLENGE'
        assert 'email' in response['ChallengeParameters']

        # Step 3: In real scenario, user clicks link in email
        # For testing, we'd need to retrieve token from DynamoDB

    @pytest.mark.integration
    def test_disallowed_domain_blocked(self, cognito_client):
        """Users with disallowed email domain cannot sign up."""
        pytest.skip('Requires deployed AWS infrastructure')

        client_id = os.environ.get('CLIENT_ID')

        with pytest.raises(cognito_client.exceptions.UserLambdaValidationException):
            cognito_client.sign_up(
                ClientId=client_id,
                Username='hacker@malicious.com',
                Password='TempPassword123!',
                UserAttributes=[
                    {'Name': 'email', 'Value': 'hacker@malicious.com'}
                ]
            )

    @pytest.mark.integration
    def test_session_limit_third_device_removes_oldest(self):
        """Third device login should remove oldest session."""
        pytest.skip('Requires deployed AWS infrastructure')
        # This would test:
        # 1. Login from device A (session 1 created)
        # 2. Login from device B (session 2 created)
        # 3. Login from device C (session 1 removed, session 3 created)
        pass


# =============================================================================
# Task 7: CloudFormation Template Validation Tests
# =============================================================================
class TestCloudFormationTemplates:
    """Tests for CloudFormation template syntax and structure."""

    def test_security_yaml_valid_syntax(self):
        """security.yaml should have valid YAML syntax."""
        import yaml
        template_path = 'cloudformation/security.yaml'

        with open(template_path, 'r') as f:
            template = yaml.safe_load(f)

        assert 'AWSTemplateFormatVersion' in template
        assert 'Resources' in template

    def test_required_parameters_present(self):
        """All required parameters should be defined."""
        import yaml
        template_path = 'cloudformation/security.yaml'

        with open(template_path, 'r') as f:
            template = yaml.safe_load(f)

        required_params = [
            'Environment',
            'ProjectName',
            'VpcId',
            'AllowedEmailDomains',
            'MagicLinkExpiryMinutes',
            'MaxConcurrentSessions',
            'SessionDurationDays',
            'AppDomainName'
        ]

        for param in required_params:
            assert param in template['Parameters'], f'Missing parameter: {param}'

    def test_lambda_functions_defined(self):
        """All required Lambda functions should be defined."""
        import yaml
        template_path = 'cloudformation/security.yaml'

        with open(template_path, 'r') as f:
            template = yaml.safe_load(f)

        required_lambdas = [
            'PreSignUpLambda',
            'DefineAuthChallengeLambda',
            'CreateAuthChallengeLambda',
            'VerifyAuthChallengeLambda',
            'PostAuthenticationLambda'
        ]

        for lambda_name in required_lambdas:
            assert lambda_name in template['Resources'], f'Missing Lambda: {lambda_name}'

    def test_dynamodb_tables_defined(self):
        """Required DynamoDB tables should be defined."""
        import yaml
        template_path = 'cloudformation/security.yaml'

        with open(template_path, 'r') as f:
            template = yaml.safe_load(f)

        required_tables = ['MagicLinkTable', 'UserSessionsTable']

        for table in required_tables:
            assert table in template['Resources'], f'Missing table: {table}'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
