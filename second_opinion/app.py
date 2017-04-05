#!/usr/bin env python
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, session, redirect, url_for
from oic.oic.provider import Provider
from oic.utils.sdb import SessionDB
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.http_util import Response
from oic.utils.http_util import get_post
import json
from oic.utils.http_util import SeeOther
from oic.utils.authz import AuthzHandling
from oic.utils.authn.client import verify_client
from oic import rndstr  # moved to oic from oic.oauth2
from oic.utils.userinfo import UserInfo

from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import EndSessionEndpoint
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger
from oic.utils.http_util import BadRequest
import credstash
import duo_web
import string
from six.moves import urllib
from oic.oauth2 import redirect_authz_error, authz_error
import logging
from http.cookies import SimpleCookie

for mod_name in ['oic']:
    logging.getLogger(mod_name).setLevel(logging.DEBUG)
    logging.getLogger(mod_name).addHandler(logging.StreamHandler())

OIDC_QUERY_ARGUMENTS = [
    'response_type',
    'client_id',
    'state',
    'prompt',
    'redirect_uri',
    'nonce',
    'scope',
    'code'
]


class UserInfoWithGroups(UserInfo):
    def filter(self, userinfo, user_info_claims=None):
        """
        Return only those claims that are asked for.
        It's a best effort task; if essential claims are not present
        no error is flagged.

        This inherited class adds the `groups` claim

        Force the addition of a `groups` claim regardless of `user_info_claims`
        to workaround this line which doesn't allow for customization of the
        `userinfo_claims`

        https://github.com/OpenIDC/pyoidc/blob/300adc8cdf1670f6c41dd28394958162ab5a213a/src/oic/oic/provider.py#L1232

        :param userinfo: A dictionary containing the available user info.
        :param user_info_claims: A dictionary specifying the asked for claims
        :return: A dictionary of filtered claims.
        """

        if user_info_claims is None:
            return copy.copy(userinfo)
        else:
            result = {}
            missing = []
            optional = []
            # Add in `groups` claim as an allowed claim
            user_info_claims['groups'] = None
            for key, restr in user_info_claims.items():
                try:
                    result[key] = userinfo[key]
                except KeyError:
                    if restr == {"essential": True}:
                        missing.append(key)
                    else:
                        optional.append(key)
            return result


class DuoAuthnMethod(UserAuthnMethod):
    url_endpoint = "/duo/verify"

    def __init__(self, app, **kwargs):
        super(DuoAuthnMethod, self).__init__(None)
        self.app = app
        self.user_db = {
            "diana": "krall",
            "babs": "howes",
            "upper": "crust"
        }

    def __call__(self, *args, **kwargs):
        login_hint = urllib.parse.parse_qs(kwargs['query'])['login_hint'][0]

        sign_function = duo_web.sign_request
        sig_request = sign_function(
            self.app.config['credentials']['second-opinion:duo:ikey'],
            self.app.config['credentials']['second-opinion:duo:skey'],
            self.app.config['credentials']['second-opinion:duo:akey'],
            login_hint.decode('utf-8', 'ignore')
        )
        body_template = string.Template(r"""
        <!DOCTYPE html>
        <html>
          <head>
            <title>Duo Authentication Prompt</title>
            <meta name='viewport' content='width=device-width, initial-scale=1'>
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <style>
              #duo_iframe {
                width: 100%;
                min-width: 304px;
                max-width: 620px;
                height: 330px;
                border: none;
              }
              body {
                text-align: center;
              }
            </style>
          </head>
          <body>
            <h1>Duo Authentication Prompt</h1>
            <script src='../static/Duo-Web-v2.js'></script>
            <iframe id="duo_iframe"
                    title="Two-Factor Authentication"
                    frameborder="0"
                    data-host="$data_host"
                    data-sig-request="$sig_request"
                    data-post-action="$data_post_action"
                    >
            </iframe>
          </body>
        </html>""")
        # Ascii encoding is a workaround for
        # https://github.com/awslabs/chalice/issues/262
        body = body_template.substitute(
            data_host=self.app.config['credentials'][
                'second-opinion:duo:data-host'],
            sig_request=sig_request,
            data_post_action=self.url_endpoint
        ).encode('ascii', 'ignore')

        # Save the OIDC query arguments in the Flask session so we can
        # access them after the Duo login and verification completes
        session['state'] = request.args
        # for argument in request.args:
        #     if argument in OIDC_QUERY_ARGUMENTS:
        #         session[argument] = request.args[argument]

        return Response(body)

    def verify(self, *args, **kwargs):

        # We don't need to validate client_id here as it will be checked at
        # the token endpoint

        # if 'client_id' not in session:
        #     return redirect_authz_error(error='invalid_request')
        #     return (
        #         "client_id wasn't found in the session which should have "
        #         "been provided in the /authorize call")
        # if session['client_id'] not in self.app.config['OP_CLIENT_DB']:
        #     return (
        #         "client_id provided in the /authorize call was not found in "
        #         "our database of registered clients")

        # presence of redirect_uri as a query argument is tested for in
        # authorization_endpoint auth_init . Since at the moment Duo is not
        # configured to pass back the inbound query arguments in the
        # callback I don't think this test will pass.

        # I need to ask kang again what the downsides are to setting the duo
        #  data-post-action which allows me to pass the query arguments back
        #  to the OP instead of using the session. The benefit of this is
        # that pyoidc then deals with this second call to the authorization
        # endpoint as if it's normal and we simply verify the duo
        # sig_response and allow or dissallow the user

        # if 'redirect_uri' not in session:
        #     return authz_error("invalid_request_uri")
        #
        # allowed_redirect_uris = self.app.config['OP_CLIENT_DB'][session[
        #     'client_id']]['redirect_uris']
        # if (list(urllib.parse.splitquery(session['redirect_uri']))
        #         not in allowed_redirect_uris):
        #     return authz_error("invalid_request_uri")

        authenticated_username = duo_web.verify_response(
            self.app.config['credentials']['second-opinion:duo:ikey'],
            self.app.config['credentials']['second-opinion:duo:skey'],
            self.app.config['credentials']['second-opinion:duo:akey'],
            request.form['sig_response']
        )
        completed = True

        if not completed:
            # TODO : I don't see a code path that brings us here but I don't
            #  understand why you'd call val as if it were a method since at
            #  least in the case of user_pass it's a string of the username
            return val(environ, start_response), False

        # TODO : I am here ! I need to return a 302 page with state and code
        #  on success to send the user back to the RP. One Duo verification
        # failure I need to maybe redirect the user back to Duo?
        # Either way, the return value here is a flask response object not a
        #  username as I'd thought from the simple_op example

        # redirect_uri = urllib.parse.urlparse(session['redirect_uri'])
        # query_pairs = urllib.parse.parse_qsl(redirect_uri.query)
        # for argument in session:
        #     if argument in OIDC_QUERY_ARGUMENTS:
        #         query_pairs.append((argument, session[argument]))
        # new_uri = urllib.parse.urlunparse(
        #     redirect_uri[0:4] +
        #     (urllib.parse.urlencode(query_pairs),) +
        #     redirect_uri[5:6])

        if authenticated_username:
            # Why in simple_op do we redirect to that /authorization
            # endpoint instead of to the redirect_uri?
            # And why set a cookie called "auth" to the
            # authenticated_username if it appears to never be used?
            #
            # So I think we have to send the user back to /authorization in
            # order to generate the 'code' and subsequently redirect them
            # back to the RP
            #
            # By my read the way that the verify method (like this one)
            # conveys authentication success is by setting a symetrically
            # encrypted cookie containing the user id (email) and a value
            # like "auth" or "samlm" or "query" or "casm" or "upm"
            #
            # I can't however determine how the /authorization endpoint then
            #  consumes this cookie to know that auth succeeded

            set_cookie, cookie_value = self.create_cookie(
                authenticated_username, "auth")
            cookie_value += "; path=/"

            # url = "{base_url}?{query_string}".format(
            #     base_url="/{}".format(AuthorizationEndpoint.etype),
            #     query_string=urllib.parse.urlencode(session['state']))
            response = redirect(
                url_for('authorization', **session['state']), 303)
            # This is to force allowing a relative URL in the Location
            # header because if we don't we end up redirecting from https to
            #  http because flask doesn't realize we're behind a reverse
            # proxy. We should probably fix this systemically
            # http://flask.pocoo.org/snippets/35/
            # however it probably doesn't matter in a lambda context
            response.autocorrect_location_header = False
            cookie = SimpleCookie(cookie_value)
            for cookie_name in cookie:
                response.set_cookie(
                    key=cookie_name,
                    value=cookie[cookie_name].value,
                    **{k: v for k, v
                       in cookie[cookie_name].iteritems()
                       if k in ['key',
                                'max_age',
                                'expires',
                                'path',
                                'domain',
                                'secure',
                                'httponly']
                       and len(cookie[cookie_name][k]) > 0})
            return response

            # return SeeOther(url, headers=[(set_cookie, cookie_value)])



            # return redirect(new_uri, 303)
        else:  # Unsuccessful authentication
            return redirect_authz_error("access_denied", new_uri)


class PyOIDCOP(object):
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.load_config()

        app.teardown_appcontext(self.teardown)  # Flask 0.9 or newer

        self.authn_broker = AuthnBroker()
        instance = DuoAuthnMethod(self.app)
        self.authn_broker.add("duo", instance)
        self.app.add_url_rule(
            rule=instance.url_endpoint,
            endpoint='verify',
            view_func=instance.verify,
            methods=['POST'])
        provider = self.get_provider()
        provider.keyjar.import_jwks(
            self.app.config['OP_JWKS_PRIVATE'], issuer='')
        provider.jwks_uri = "{}{}".format(
            provider.baseurl,
            self.app.config['OP_JWKS_ROUTE']
        )

        # /.well-known/jwks.json
        @self.app.route(self.app.config['OP_JWKS_ROUTE'])
        def jwks():
            return jsonify(provider.keyjar.export_jwks(private=False))

        # /authorization
        @self.app.route(
            "/{}".format(AuthorizationEndpoint.etype),
            methods=['GET', 'POST'])
        def authorization():
            a = provider.authorization_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

            # return (a.message, a.status, a.headers)
            return a

        # /token
        @self.app.route(
            "/{}".format(TokenEndpoint.etype),
            methods=['POST'])
        def token():
            return provider.token_endpoint(
                request=request.values.to_dict(),
                dtype='dict',
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /userinfo
        @self.app.route("/{}".format(UserinfoEndpoint.etype))
        def userinfo():
            return provider.userinfo_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; '),
                authn=request.headers.get('Authorization', '')
            )

        # /registration
        @self.app.route("/{}".format(RegistrationEndpoint.etype))
        def registration():
            return provider.registration_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /end_session
        @self.app.route("/{}".format(EndSessionEndpoint.etype))
        def end_session():
            return provider.endsession_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /.well-known/openid-configuration
        @self.app.route("/.well-known/openid-configuration")
        def providerinfo():
            return provider.providerinfo_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /.well-known/webfinger
        @self.app.route("/.well-known/webfinger")
        def webfinger():
            if request.values["rel"] == OIC_ISSUER:
                wf = WebFinger()
                return Response(
                    wf.response(
                        request.values["resource"],
                        provider.baseurl
                    )), [("Content-Type", "application/jrd+json")]
            else:
                return BadRequest("Incorrect webfinger.")

        # /static
        # Served automatically from the static directory
        # http://flask.pocoo.org/docs/0.12/quickstart/#static-files

        @app.route('/user', methods=['GET', 'POST'])
        def user():
            if 'login_hint' in request.values:
                email = request.values['login_hint']
            else:
                email = 'user@example.com'
            if request.method == 'POST':
                authenticated_username = duo_web.verify_response(
                    self.app.config['credentials']['second-opinion:duo:ikey'],
                    self.app.config['credentials']['second-opinion:duo:skey'],
                    self.app.config['credentials']['second-opinion:duo:akey'],
                    request.form['sig_response']
                )
                if authenticated_username:
                    return "<h1>Success %s</h1>" % authenticated_username
            elif request.method == 'GET':
                sign_function = duo_web.sign_request
                sig_request = sign_function(
                    self.app.config['credentials']['second-opinion:duo:ikey'],
                    self.app.config['credentials']['second-opinion:duo:skey'],
                    self.app.config['credentials']['second-opinion:duo:akey'],
                    email
                )
                body_template = string.Template(r"""
        <!DOCTYPE html>
        <html>
          <head>
            <title>Duo Authentication Prompt</title>
            <meta name='viewport' content='width=device-width, initial-scale=1'>
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <style>
              #duo_iframe {
                width: 100%;
                min-width: 304px;
                max-width: 620px;
                height: 330px;
                border: none;
              }
              body {
                text-align: center;
              }
            </style>
          </head>
          <body>
            <h1>Duo Authentication Prompt</h1>
            <script src='../static/Duo-Web-v2.js'></script>
            <iframe id="duo_iframe"
                    title="Two-Factor Authentication"
                    frameborder="0"
                    data-host="$data_host"
                    data-sig-request="$sig_request"
                    >
            </iframe>
          </body>
        </html>""")
                # Ascii encoding is a workaround for
                # https://github.com/awslabs/chalice/issues/262
                body = body_template.substitute(
                    data_host=self.app.config['credentials'][
                        'second-opinion:duo:data-host'],
                    sig_request=sig_request
                ).encode('ascii', 'ignore')
                return body

    def load_config(self):
        self.app.config['credentials'] = credstash.getAllSecrets(
            context={'application': 'second-opinion'},
            credential='second-opinion:*',
            region="us-west-2"
        )

        self.app.logger.info(
            credstash.getSecret('second-opinion:duo:data-host',
                                region="us-west-2",
                                context={'application': 'second-opinion'}))

        # self.app.config.setdefault('OP_BASE_URL',
        #                            'https://op.example.com')
        # self.app.config.setdefault('OP_PORT', 443)
        # self.app.config.setdefault(
        #     'OP_ISSUER',
        #     self.app.config['OP_BASE_URL'].rstrip("/") + ':' +
        #     str(self.app.config['OP_PORT']))
        self.app.config.setdefault(
            'DEBUG',
            True)
        self.app.config[
            'SECRET_KEY'] = 'SECRET KEY VALUE GETS OVERRIDDEN FROM HERE'
        self.app.config.setdefault(
            'OP_ISSUER',
            'https://op.example.com')
        self.app.config.setdefault(
            'OP_CLIENT_DB',
            {
                'aaaaaaaaaaaa': {
                    'client_secret': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'redirect_uris': [
                        ['https://rp.example.com/second-opinion/redirect_uri',
                         None]],
                    'client_salt': 'aaaaaaaa',
                    'client_id': 'aaaaaaaaaaaa',
                    'token_endpoint_auth_method': 'client_secret_post'
                }
            }
        )
        self.app.config.setdefault(
            'OP_KEY_CONFIG',
            [
                {'use': ['enc', 'sig'],
                 'type': 'RSA',
                 'key': 'keys/key.pem'},
                {'use': ['sig'],
                 'type': 'EC',
                 'crv': 'P-256'},
                {'use': ['enc'],
                 'type': 'EC',
                 'crv': 'P-256'}]
        )
        self.app.config.setdefault(
            'OP_JWKS_ROUTE',
            '/.well-known/jwks.json'
        )

        # TODO : Establish way to pull config from credstash
        self.app.config.setdefault(
            'OP_JWKS_PRIVATE', 'KEY DATA STRUCTURE WILL GO HERE'
        )

        self.app.config.setdefault(
            'OP_USERINFO',
            {
                "user@example.com": {
                    "sub": "ad|second-opinion-dev|user@example.com",
                    "name": "Diana Krall",
                    "given_name": "Diana",
                    "family_name": "Krall",
                    "nickname": "Dina",
                    "email": "user@example.com",
                    "email_verified": True,
                    "phone_number": "+46 90 7865000",
                    "address": {
                        "street_address": "Ume Universitet",
                        "locality": "Ume",
                        "postal_code": "SE-90187",
                        "country": "Sweden"
                    },
                    "groups": [
                        "foo",
                        "bar",
                    ]
                },
                "babs": {
                    "sub": "babs0001",
                    "name": "Barbara J Jensen",
                    "given_name": "Barbara",
                    "family_name": "Jensen",
                    "nickname": "babs",
                    "email": "babs@example.com",
                    "email_verified": True,
                    "address": {
                        "street_address": "100 Universal City Plaza",
                        "locality": "Hollywood",
                        "region": "CA",
                        "postal_code": "91608",
                        "country": "USA"
                    }
                },
                "upper": {
                    "sub": "uppe0001",
                    "name": "Upper Crust",
                    "given_name": "Upper",
                    "family_name": "Crust",
                    "email": "uc@example.com",
                    "email_verified": True
                }
            }
        )

    def teardown(self, exception):
        pass  # teardown actions

    def get_provider(self):
        provider = Provider(
            name=self.app.config['OP_ISSUER'],
            sdb=SessionDB(self.app.config['OP_ISSUER']),
            cdb=self.app.config['OP_CLIENT_DB'],
            authn_broker=self.authn_broker,
            userinfo=UserInfoWithGroups(self.app.config['OP_USERINFO']),
            authz=AuthzHandling(),
            client_authn=verify_client,
            symkey=None)
        provider.baseurl = self.app.config['OP_ISSUER']
        provider.symkey = rndstr(16)
        return provider


app = Flask(__name__)
op = PyOIDCOP(app)
