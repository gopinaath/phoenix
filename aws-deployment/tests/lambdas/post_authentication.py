"""Post Authentication Lambda handler - session management."""
import os
import time
import uuid
import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    """
    Post Authentication: Enforces max concurrent sessions.
    Removes oldest session if limit exceeded.
    """
    table_name = os.environ['SESSIONS_TABLE']
    max_sessions = int(os.environ.get('MAX_SESSIONS', 2))
    session_days = int(os.environ.get('SESSION_DURATION_DAYS', 7))

    table = dynamodb.Table(table_name)
    user_sub = event['request']['userAttributes']['sub']

    # Generate new session ID
    session_id = str(uuid.uuid4())
    ttl = int(time.time()) + (session_days * 24 * 60 * 60)

    # Get all active sessions for this user
    response = table.query(
        KeyConditionExpression=Key('userId').eq(user_sub)
    )
    sessions = response.get('Items', [])

    # Filter out expired sessions
    current_time = int(time.time())
    active_sessions = [s for s in sessions if s.get('ttl', 0) > current_time]

    # If at limit, remove oldest session(s)
    if len(active_sessions) >= max_sessions:
        # Sort by creation time, remove oldest
        active_sessions.sort(key=lambda x: x.get('createdAt', 0))
        sessions_to_remove = active_sessions[:len(active_sessions) - max_sessions + 1]

        for old_session in sessions_to_remove:
            table.delete_item(Key={
                'userId': user_sub,
                'sessionId': old_session['sessionId']
            })

    # Create new session
    table.put_item(Item={
        'userId': user_sub,
        'sessionId': session_id,
        'createdAt': int(time.time()),
        'ttl': ttl,
        'email': event['request']['userAttributes'].get('email', ''),
        'deviceInfo': event['request'].get('clientMetadata', {}).get('deviceInfo', 'unknown')
    })

    return event
