import time
import jwt
from flask import request, session
from flask_restx import Resource, fields

from mindsdb.__about__ import __version__ as mindsdb_version
from mindsdb.api.http.namespaces.configs.default import ns_conf
from mindsdb.api.http.utils import http_error
from mindsdb.metrics.metrics import api_endpoint_metrics
from mindsdb.utilities.config import Config
from mindsdb.utilities import log

logger = log.getLogger(__name__)

JWT_ALGORITHM = 'HS256'

def get_jwt_secret():
    config = Config()
    return config['auth'].get('jwt_secret', 'default_jwt_secret_change_me')

def create_token(username, token_type='access'):
    now = int(time.time())
    if token_type == 'access':
        exp = now + 3600  # 1 hour
    elif token_type == 'refresh':
        exp = now + 7*24*3600  # 7 days
    else:
        raise ValueError('Invalid token type')

    payload = {
        'username': username,
        'type': token_type,
        'iat': now,
        'exp': exp
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def check_auth() -> bool:
    config = Config()
    if config['auth']['http_auth_enabled'] is False:
        return True

    auth_header = request.headers.get('Authorization')
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            token = parts[1]
            try:
                payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
            except jwt.ExpiredSignatureError:
                logger.warning("Token expired")
                return False
            except jwt.InvalidTokenError:
                logger.warning("Invalid token")
                return False

            if payload.get('type') != 'access':
                return False

            username = payload.get('username')
            if username != config['auth']['username']:
                return False

            return True

    # fallback to old session check
    if config['auth'].get('provider') == 'cloud':
        if isinstance(session.get('username'), str) is False:
            return False

        if config['auth']['oauth']['tokens']['expires_at'] < time.time():
            return False

        return True

    return session.get('username') == config['auth']['username']

@ns_conf.route('/login', methods=['POST'])
class LoginRoute(Resource):
    @ns_conf.doc(
        responses={
            200: 'Success',
            400: 'Error in username or password',
            401: 'Invalid username or password'
        },
        body=ns_conf.model('request_login', {
            'username': fields.String(description='Username'),
            'password': fields.String(description='Password')
        })
    )
    @api_endpoint_metrics('POST', '/default/login')
    def post(self):
        ''' Check user's credentials and creates a session or returns JWT tokens
        '''
        username = request.json.get('username')
        password = request.json.get('password')
        if (
            not isinstance(username, str) or len(username) == 0
            or not isinstance(password, str) or len(password) == 0
        ):
            return http_error(
                400, 'Error in username or password',
                'Username and password should be non-empty strings'
            )

        config = Config()
        inline_username = config['auth']['username']
        inline_password = config['auth']['password']

        if username != inline_username or password != inline_password:
            return http_error(
                401, 'Forbidden',
                'Invalid username or password'
            )

        access_token = create_token(username, 'access')
        refresh_token = create_token(username, 'refresh')

        # Keep old session behavior for compatibility
        session.clear()
        session['username'] = username
        session.permanent = True

        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }, 200

@ns_conf.route('/refresh', methods=['POST'])
class RefreshRoute(Resource):
    @ns_conf.doc(
        responses={
            200: 'Success',
            401: 'Invalid or expired refresh token',
            400: 'Bad request'
        },
        body=ns_conf.model('request_refresh', {
            'refresh_token': fields.String(description='Refresh token')
        })
    )
    @api_endpoint_metrics('POST', '/default/refresh')
    def post(self):
        ''' Exchange a refresh token for a new access token
        '''
        refresh_token = request.json.get('refresh_token')
        if not isinstance(refresh_token, str) or len(refresh_token) == 0:
            return http_error(400, 'Bad request', 'Refresh token is required')

        try:
            payload = jwt.decode(refresh_token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return http_error(401, 'Unauthorized', 'Refresh token expired')
        except jwt.InvalidTokenError:
            return http_error(401, 'Unauthorized', 'Invalid refresh token')

        if payload.get('type') != 'refresh':
            return http_error(401, 'Unauthorized', 'Invalid token type')

        username = payload.get('username')
        config = Config()
        if username != config['auth']['username']:
            return http_error(401, 'Unauthorized', 'Invalid token username')

        new_access_token = create_token(username, 'access')
        return {'access_token': new_access_token}, 200

@ns_conf.route('/logout', methods=['POST'])
class LogoutRoute(Resource):
    @ns_conf.doc(
        responses={
            200: 'Success'
        }
    )
    @api_endpoint_metrics('POST', '/default/logout')
    def post(self):
        session.clear()
        return '', 200

@ns_conf.route('/status')
class StatusRoute(Resource):
    @ns_conf.doc(
        responses={
            200: 'Success'
        },
        model=ns_conf.model('response_status', {
            'environment': fields.String(description='The name of current environment: cloud, local or other'),
            'mindsdb_version': fields.String(description='Current version of mindsdb'),
            'auth': fields.Nested(
                ns_conf.model('response_status_auth', {
                    'confirmed': fields.Boolean(description='is current user authenticated'),
                    'http_auth_enabled': fields.Boolean(description='is authenticated required'),
                    'provider': fields.String(description='current authenticated provider: local or 3rd-party or disabled')
                })
            )
        })
    )
    @api_endpoint_metrics('GET', '/default/status')
    def get(self):
        environment = 'local'
        config = Config()

        environment = config.get('environment')
        if environment is None:
            if config.get('cloud', False):
                environment = 'cloud'
            elif config.get('aws_marketplace', False):
                environment = 'aws_marketplace'
            else:
                environment = 'local'

        auth_provider = 'disabled'
        if config['auth']['http_auth_enabled'] is True:
            if config['auth'].get('provider') is not None:
                auth_provider = config['auth'].get('provider')
            else:
                auth_provider = 'local'

        resp = {
            'mindsdb_version': mindsdb_version,
            'environment': environment,
            'auth': {
                'confirmed': check_auth(),
                'http_auth_enabled': config['auth']['http_auth_enabled'],
                'provider': auth_provider
            }
        }

        return resp
