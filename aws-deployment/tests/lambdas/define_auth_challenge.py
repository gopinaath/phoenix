"""Define Auth Challenge Lambda handler."""


def handler(event, context):
    """
    Define Auth Challenge: Orchestrates the magic link auth flow.
    """
    session = event['request'].get('session', [])

    if len(session) == 0:
        # First call: Issue CUSTOM_CHALLENGE to send magic link
        event['response']['issueTokens'] = False
        event['response']['failAuthentication'] = False
        event['response']['challengeName'] = 'CUSTOM_CHALLENGE'
    elif len(session) == 1:
        # Second call: Check if magic link was verified
        last = session[-1]
        if last.get('challengeName') == 'CUSTOM_CHALLENGE':
            if last.get('challengeResult') == True:
                # Magic link verified, issue tokens
                event['response']['issueTokens'] = True
                event['response']['failAuthentication'] = False
            else:
                # Invalid magic link
                event['response']['issueTokens'] = False
                event['response']['failAuthentication'] = True
        else:
            event['response']['issueTokens'] = False
            event['response']['failAuthentication'] = True
    else:
        # Too many attempts
        event['response']['issueTokens'] = False
        event['response']['failAuthentication'] = True

    return event
