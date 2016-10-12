# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import (datetime, timedelta)

import jwt

from h import models
from h.util.view import json_view


class OAuthTokenError(Exception):
    def __init__(self, message, description=None, status_code=400):
        self.description = description
        self.status_code = status_code
        super(OAuthTokenError, self).__init__(message)


@json_view(route_name='token', request_method='POST')
def access_token(request):
    grant_token = _validate_request(request)
    userid = _extract_userid(request, grant_token)

    user = request.db.query(models.User).filter_by(userid=userid).one_or_none()
    if user is None:
        raise OAuthTokenError('invalid_grant',
                              description='user with userid described in subject could not be found')

    expires_in = timedelta(hours=1)
    token = models.Token(userid=user.userid, expires=(utcnow() + expires_in))
    request.db.add(token)

    return {
        'access_token': token.value,
        'token_type': 'bearer',
        'expires_in': expires_in.seconds,
    }


@json_view(context=OAuthTokenError)
def api_token_error(context, request):
    """Handle an expected/deliberately thrown API exception."""
    request.response.status_code = context.status_code
    resp = {'error': context.message}
    if context.description:
        resp['error_description'] = context.description
    return resp


def _validate_request(request):
    grant_type = request.POST.get('grant_type')
    if grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        raise OAuthTokenError('unsupported_grant_type',
                              description='specified grant type is not supported')

    grant_token = request.POST.get('assertion')
    if not grant_token:
        raise OAuthTokenError('invalid_request',
                              description='required assertion parameter is missing')

    return grant_token


def _extract_userid(request, grant_token):
    try:
        unverified_grants = jwt.decode(grant_token, verify=False)
    except jwt.DecodeError:
        raise OAuthTokenError('invalid_grant',
                              description='parameter assertion is not a JWT token')

    client_id = unverified_grants.get('iss', None)
    if not client_id:
        raise OAuthTokenError('invalid_grant', description='grant token issuer is missing')

    authclient = request.db.query(models.AuthClient).get(client_id)
    if not authclient:
        raise OAuthTokenError('invalid_grant',
                              description='given JWT issuer is invalid')

    try:
        claims = jwt.decode(grant_token,
                            algorithms=['HS256'],
                            audience=request.domain,
                            key=authclient.secret,
                            leeway=10)
        userid = claims.get('sub')
        if not userid:
            raise OAuthTokenError('invalid_grant',
                                  description='JWT subject is missing')

        return userid
    except jwt.DecodeError:
        raise OAuthTokenError('invalid_grant',
                              description='invalid JWT signature')
    except jwt.exceptions.InvalidAlgorithmError:
        raise OAuthTokenError('invalid_grant',
                              description='invalid JWT signature algorithm')
    except jwt.InvalidAudienceError:
        raise OAuthTokenError('invalid_grant',
                              description='invalid JWT audience')
    except jwt.ImmatureSignatureError:
        raise OAuthTokenError('invalid_grant',
                              description='JWT not before is in the future')
    except jwt.ExpiredSignatureError:
        raise OAuthTokenError('invalid_grant',
                              description='JWT token is expired')
    except jwt.InvalidIssuedAtError:
        raise OAuthTokenError('invalid_grant',
                              description='JWT issued at is in the future')


def utcnow():
    return datetime.utcnow()
