# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from calendar import timegm
from datetime import (datetime, timedelta)

import jwt
import pytest

from h import models
from h.views import api_auth as views


class TestAccessToken(object):
    def test_it_creates_a_token(self, pyramid_request, claims, authclient, db_session):
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        assert db_session.query(models.Token).filter_by(userid=claims['sub']).count() == 0
        views.access_token(pyramid_request)
        assert db_session.query(models.Token).filter_by(userid=claims['sub']).count() == 1

    def test_the_new_token_expires_within_one_hour(self, pyramid_request, claims, authclient, db_session, utcnow):
        utcnow.return_value = datetime(2016, 1, 1, 3, 0, 0)

        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        views.access_token(pyramid_request)

        token = db_session.query(models.Token).filter_by(userid=claims['sub']).first()
        assert token.expires == datetime(2016, 1, 1, 4, 0, 0)

    def test_it_returns_a_oauth_compliant_response(self, pyramid_request, claims, authclient, db_session):
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        result = views.access_token(pyramid_request)

        token = db_session.query(models.Token).filter_by(userid=claims['sub']).first()

        assert result == {
            'access_token': token.value,
            'token_type': 'bearer',
            'expires_in': 3600,
        }

    def test_it_succeeds_with_expired_token_and_leeway(self, pyramid_request, claims, authclient, db_session):
        claims['exp'] = self.epoch(delta=timedelta(seconds=-5))
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        assert db_session.query(models.Token).filter_by(userid=claims['sub']).count() == 0
        views.access_token(pyramid_request)
        assert db_session.query(models.Token).filter_by(userid=claims['sub']).count() == 1

    def test_missing_grant_type(self, pyramid_request, claims, authclient):
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'unsupported_grant_type'
        assert 'grant type is not supported' in exc.value.description

    def test_unsupported_grant_type(self, pyramid_request, claims, authclient):
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'authorization_code'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'unsupported_grant_type'

    def test_missing_assertion_parameter(self, pyramid_request):
        pyramid_request.POST = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_request'

    def test_non_jwt_assertion_parameter(self, pyramid_request):
        pyramid_request.POST = {'assertion': 'bogus', 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'assertion is not a JWT token' in exc.value.description

    def test_missing_jwt_issuer(self, pyramid_request, claims, authclient):
        del claims['iss']
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'issuer is missing' in exc.value.description

    def test_empty_jwt_issuer(self, pyramid_request, claims, authclient):
        claims['iss'] = ''
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'issuer is missing' in exc.value.description

    def test_missing_authclient_with_given_jwt_issuer(self, pyramid_request, db_session, claims, authclient):
        db_session.delete(authclient)
        db_session.flush()

        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'issuer is invalid' in exc.value.description

    def test_signed_with_different_secret(self, pyramid_request, claims):
        tok = self.jwt_token(claims, 'different-secret')
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'invalid JWT signature' in exc.value.description

    def test_signed_with_unsupported_algorithm(self, pyramid_request, claims, authclient):
        tok = self.jwt_token(claims, authclient.secret, algorithm='HS512')
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'invalid JWT signature algorithm' in exc.value.description

    def test_invalid_audience(self, pyramid_request, claims, authclient):
        claims['aud'] = 'foobar.org'
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'invalid JWT audience' in exc.value.description

    def test_not_before_in_the_future(self, pyramid_request, claims, authclient):
        claims['nbf'] = self.epoch(delta=timedelta(minutes=5))
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'not before is in the future' in exc.value.description

    def test_expired_with_leeway_in_the_past(self, pyramid_request, claims, authclient):
        claims['exp'] = self.epoch(delta=timedelta(minutes=-2))
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'token is expired' in exc.value.description

    def test_issued_at_in_the_future(self, pyramid_request, claims, authclient):
        claims['iat'] = self.epoch(delta=timedelta(minutes=2))
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'issued at is in the future' in exc.value.description

    def test_missing_sub(self, pyramid_request, claims, authclient):
        del claims['sub']
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'subject is missing' in exc.value.description

    def test_empty_sub(self, pyramid_request, claims, authclient):
        claims['sub'] = ''
        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'subject is missing' in exc.value.description

    def test_user_not_found(self, pyramid_request, claims, authclient, db_session, user):
        db_session.delete(user)
        db_session.flush()

        tok = self.jwt_token(claims, authclient.secret)
        pyramid_request.POST = {'assertion': tok, 'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer'}

        with pytest.raises(views.OAuthTokenError) as exc:
            views.access_token(pyramid_request)

        assert exc.value.message == 'invalid_grant'
        assert 'user with userid described in subject could not be found' in exc.value.description

    @pytest.fixture
    def claims(self, authclient, user, pyramid_request):
        return {
            'iss': authclient.id,
            'sub': user.userid,
            'aud': pyramid_request.domain,
            'exp': self.epoch(delta=timedelta(minutes=10)),
            'nbf': self.epoch(),
            'iat': self.epoch(),
        }

    @pytest.fixture
    def authclient(self, db_session):
        client = models.AuthClient(authority='partner.org', secret='bogus')
        db_session.add(client)
        db_session.flush()
        return client

    @pytest.fixture
    def user(self, factories, db_session, authclient):
        user = factories.User(authority=authclient.authority)
        db_session.add(user)
        db_session.flush()
        return user

    @pytest.fixture
    def utcnow(self, patch):
        return patch('h.views.api_auth.utcnow')

    def jwt_token(self, claims, secret, algorithm='HS256'):
        return jwt.encode(claims, secret, algorithm=algorithm)

    def epoch(self, timestamp=None, delta=None):
        if timestamp is None:
            timestamp = datetime.utcnow()

        if delta is not None:
            timestamp = timestamp + delta

        return timegm(timestamp.utctimetuple())


class TestAPITokenError(object):
    def test_it_sets_the_response_status_code(self, pyramid_request):
        context = views.OAuthTokenError('the-error', status_code=403)
        views.api_token_error(context, pyramid_request)
        assert pyramid_request.response.status_code == 403

    def test_it_returns_the_error(self, pyramid_request):
        context = views.OAuthTokenError('error type')
        result = views.api_token_error(context, pyramid_request)
        assert result['error'] == 'error type'

    def test_it_returns_error_description(self, pyramid_request):
        context = views.OAuthTokenError('error type',
                                        description='error description')
        result = views.api_token_error(context, pyramid_request)
        assert result['error_description'] == 'error description'

    def test_it_skips_description_when_missing(self, pyramid_request):
        context = views.OAuthTokenError('error type')
        result = views.api_token_error(context, pyramid_request)
        assert 'error_description' not in result

    def test_it_skips_description_when_empty(self, pyramid_request):
        context = views.OAuthTokenError('error type', description='')
        result = views.api_token_error(context, pyramid_request)
        assert 'error_description' not in result
