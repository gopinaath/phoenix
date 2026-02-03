"""Verify Auth Challenge Lambda handler - validates magic link token."""
import os
import time
import boto3

dynamodb = boto3.resource('dynamodb')


def handler(event, context):
    """
    Verify Auth Challenge: Validates the magic link token.
    """
    table_name = os.environ['MAGIC_LINK_TABLE']
    table = dynamodb.Table(table_name)

    # Get the token from user's response
    challenge_answer = event['request'].get('challengeAnswer', '')
    user_sub = event['request']['userAttributes']['sub']

    # Verify token matches and is valid
    if not challenge_answer:
        event['response']['answerCorrect'] = False
        return event

    try:
        response = table.get_item(Key={'token': challenge_answer})
        item = response.get('Item')

        if not item:
            print('Token not found')
            event['response']['answerCorrect'] = False
            return event

        # Check token is for this user
        if item.get('userSub') != user_sub:
            print('Token user mismatch')
            event['response']['answerCorrect'] = False
            return event

        # Check not expired
        if item.get('ttl', 0) < int(time.time()):
            print('Token expired')
            event['response']['answerCorrect'] = False
            return event

        # Check not already used
        if item.get('used', False):
            print('Token already used')
            event['response']['answerCorrect'] = False
            return event

        # Mark token as used
        table.update_item(
            Key={'token': challenge_answer},
            UpdateExpression='SET used = :used',
            ExpressionAttributeValues={':used': True}
        )

        event['response']['answerCorrect'] = True

    except Exception as e:
        print(f'Error verifying token: {e}')
        event['response']['answerCorrect'] = False

    return event
