"""Create Auth Challenge Lambda handler - generates magic link."""
import os
import secrets
import time
import boto3

dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')


def handler(event, context):
    """
    Create Auth Challenge: Generates magic link and sends email.
    """
    table_name = os.environ['MAGIC_LINK_TABLE']
    expiry_minutes = int(os.environ.get('MAGIC_LINK_EXPIRY_MINUTES', 15))
    app_domain = os.environ['APP_DOMAIN']
    from_email = os.environ['FROM_EMAIL']

    email = event['request']['userAttributes']['email']
    user_sub = event['request']['userAttributes']['sub']

    # Generate secure token
    token = secrets.token_urlsafe(32)
    ttl = int(time.time()) + (expiry_minutes * 60)

    # Store token in DynamoDB
    table = dynamodb.Table(table_name)
    table.put_item(Item={
        'token': token,
        'email': email,
        'userSub': user_sub,
        'ttl': ttl,
        'used': False
    })

    # Create magic link URL
    magic_link = f'https://{app_domain}/auth/verify?token={token}'

    # Send email via SES
    try:
        ses.send_email(
            Source=from_email,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Sign in to Phoenix'},
                'Body': {
                    'Html': {
                        'Data': f'''
                        <html>
                        <body style="font-family: Arial, sans-serif; padding: 20px;">
                            <h2>Sign in to Phoenix</h2>
                            <p>Click the button below to sign in. This link expires in {expiry_minutes} minutes.</p>
                            <p style="margin: 30px 0;">
                                <a href="{magic_link}"
                                   style="background-color: #4F46E5; color: white; padding: 12px 24px;
                                          text-decoration: none; border-radius: 6px; display: inline-block;">
                                    Sign in to Phoenix
                                </a>
                            </p>
                            <p style="color: #666; font-size: 12px;">
                                If you didn't request this email, you can safely ignore it.
                            </p>
                        </body>
                        </html>
                        '''
                    },
                    'Text': {
                        'Data': f'Sign in to Phoenix:\n\n{magic_link}\n\nThis link expires in {expiry_minutes} minutes.'
                    }
                }
            }
        )
    except Exception as e:
        print(f'Failed to send email: {e}')
        raise Exception('Failed to send magic link email')

    # Return challenge metadata
    event['response']['publicChallengeParameters'] = {
        'email': email,
        'message': 'Magic link sent to your email'
    }
    event['response']['privateChallengeParameters'] = {
        'token': token
    }

    return event
