"""Pre Sign-Up Lambda handler for email domain validation."""
import os


def handler(event, context):
    """
    Cognito Pre Sign-up trigger:
    1. Validates email domain against allow-list
    2. Auto-confirms user (no password needed for magic link flow)
    3. Auto-verifies email
    """
    allowed_domains = os.environ.get('ALLOWED_DOMAINS', '').split(',')
    allowed_domains = [d.strip().lower() for d in allowed_domains if d.strip()]

    email = event['request']['userAttributes'].get('email', '')

    if not email:
        raise Exception('Email is required')

    email_domain = email.lower().split('@')[-1]

    if allowed_domains and email_domain not in allowed_domains:
        raise Exception(f'Email domain {email_domain} is not allowed')

    # Auto-confirm and verify for magic link flow
    event['response']['autoConfirmUser'] = True
    event['response']['autoVerifyEmail'] = True

    return event
