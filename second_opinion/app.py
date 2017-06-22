#!/usr/bin env python
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, session, redirect, url_for
from oic.oic.provider import Provider
from oic.utils.sdb import SessionDB
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.http_util import Response
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
from six.moves.http_cookies import SimpleCookie
from oic.oauth2 import redirect_authz_error
import logging
import json
import os
from joblib import Memory
import requests
import gnupg
import hashlib
import StringIO
import boto3

AWS_LAMBDA_TMP_DIR = '/tmp'
SIGNING_ROOT_AUTHORITY_FINGERPRINTS = [
    '85914504D0BFA220E93A6D25B40E5BDC92377335']
SIGNER_MAP_URL = 's3://infosec-internal-data/second-opinion/prod/signer-map.json'
SIGNER_MAP_SIG_URL = 's3://infosec-internal-data/second-opinion/prod/signer-map.asc'
memory = Memory(cachedir=AWS_LAMBDA_TMP_DIR)
gpg = gnupg.GPG(homedir=AWS_LAMBDA_TMP_DIR)


class UserInfoWithGroups(UserInfo):
    def filter(self, userinfo, user_info_claims=None):
        """Return only those claims that are asked for.
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
    def __init__(self, app, **kwargs):
        super(DuoAuthnMethod, self).__init__(None)
        self.app = app

    def __call__(self, *args, **kwargs):
        """Build and return a Duo Security login page using the login_hint
        value passed in the query string.

        Also store the query string arguments in the user's session (client
        side cookie) so they can be re-read when the user returns after
        authenticating with Duo Security.

        :param str kwargs['query']: The query string passed in the initial
        /authorize GET request
        :return: A Response object containing the web page with the Duo
        Security iframe
        """
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
            data_post_action=self.app.config['OP_DUO_VERIFY_ROUTE']
        ).encode('ascii', 'ignore')

        # Save the OIDC query arguments in the Flask session so we can
        # access them after the Duo login and verification completes
        session['state'] = request.args
        return Response(body)

    def verify(self, *args, **kwargs):
        """Verify the signed response (sig_repsonse) that the user POSTs to
        the OP_DUO_VERIFY_ROUTE by calling Duo Security to verify the
        signature.

        If the signed response is valid, create a symmetrically encrypted
        cookie with the user's verified username and redirect the user back to
        the /authorization route with the original query arguments attached
        that we temporarily stored in the Flask session. This will cause the
        user to hit the /authorization endpoint in the same way that they did
        initially but this time with an encrypted cookie showing that they're
        authenticated.

        Once the user hits the /authorization endpoint with the encrypted
        cookie they will get redirected to the RP callback with state and
        code query arguments.

        request.form['sig_response']
        session['state']

        :param args:
        :param kwargs:
        :return:
        """

        # We don't need to validate client_id here as it will be checked at
        # the token endpoint

        authenticated_username = duo_web.verify_response(
            self.app.config['credentials']['second-opinion:duo:ikey'],
            self.app.config['credentials']['second-opinion:duo:skey'],
            self.app.config['credentials']['second-opinion:duo:akey'],
            request.form['sig_response']
        )

        # The behaviour seen in other pyoidc UserAuthnMethod classes returns
        #  both the authenticated username and a boolean `completed` value.
        # We don't do that here and that may prevent multi-auth from
        # working. We instead return a Response object (instead of a
        # username, completed tuple).

        if authenticated_username:
            set_cookie, cookie_value = self.create_cookie(
                authenticated_username, "auth")
            cookie_value += "; path=/"
            response = redirect(
                url_for('authorization', **session['state']), 303)

            # autocorrect_location_header is to force allowing a relative
            # URL in the Location header because if we don't we end up
            # redirecting from https to http because flask doesn't realize
            # we're behind a reverse proxy. We should probably fix this
            # systemically http://flask.pocoo.org/snippets/35/
            # however it probably doesn't matter when deployed in lambda
            # and no longer behind a reverse proxy
            response.autocorrect_location_header = False

            # Convert the cookie_value string created by self.create_cookie
            # into calls to response.set_cookie so Flask can set the cookies
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
        else:  # Unsuccessful authentication
            return redirect_authz_error(
                "access_denied", url_for('authorization'))


class PyOIDCOP(object):
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask app.

        Load configuration settings
        Create the Authn Broker
        Add the Duo Security authentication method to the Authn Broker
        Bind the OP_DUO_VERIFY_ROUTE route to the DuoAuthnMethod
          verify method for users returning after entering their Duo code
        Create the OpenID Connect Provider
        Setup each of the OpenID Connect OP endpoints and route them to the
          associated URL path

        :param app: The Flask app object
        :return:
        """
        self.load_config()

        if self.app.config['DEBUG']:
            # Set each library's logging level to DEBUG
            for mod_name in ['oic']:
                logging.getLogger(mod_name).setLevel(logging.DEBUG)
                logging.getLogger(mod_name).addHandler(logging.StreamHandler())

        app.teardown_appcontext(self.teardown)  # Flask 0.9 or newer

        self.authn_broker = AuthnBroker()
        duo_auth_instance = DuoAuthnMethod(self.app)
        self.authn_broker.add("duo", duo_auth_instance)

        # /duo/verify
        self.app.add_url_rule(
            rule=self.app.config['OP_DUO_VERIFY_ROUTE'],
            endpoint='verify',
            view_func=duo_auth_instance.verify,
            methods=['POST'])

        client_id = request.args.get('client_id', None)
        provider = self.get_provider(self.get_userinfo(client_id))

        # /.well-known/jwks.json
        @self.app.route(self.app.config['OP_JWKS_ROUTE'])
        def jwks():
            return jsonify(provider.keyjar.export_jwks(private=False))

        # /authorization
        @self.app.route(
            "/{}".format(AuthorizationEndpoint.etype),
            methods=['GET', 'POST'])
        def authorization():
            return provider.authorization_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

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

    def load_config(self):
        """Build the configuration by overlaying DEFAULTS with environment
        variables and with config drawn from the CONFIG_URL page. Add in
        secrets from credstash. Add in authorization data for the users of
        each relying party.

        :return:
        """

        # Establish default configuration values
        DEFAULTS = {
            'DEBUG': True,
            'OP_ISSUER': 'https://second-opinion.security.allizom.org',
            'OP_JWKS_ROUTE': '/.well-known/jwks.json',
            'OP_DUO_VERIFY_ROUTE': '/duo/verify',
            'OP_USERINFO': {},
            'OP_CLIENT_DB': {}
        }

        app.config.update(DEFAULTS)

        # Override the defaults with any environment variables
        for v in [x for x in os.environ if x in DEFAULTS]:
            self.app.config[v] = os.environ.get(v)

        # Fetch the signer map
        self.app.config['SIGNER_MAP'] = self.fetch_and_verify(
            SIGNER_MAP_URL,
            SIGNER_MAP_SIG_URL,
            SIGNING_ROOT_AUTHORITY_FINGERPRINTS,
            {}
        )

        # Fetch the hosted config
        if 'CONFIG_URL' in os.environ:
            fetched_config = self.fetch_and_verify(
                os.environ.get('CONFIG_URL'),
                os.environ.get('CONFIG_SIG_URL'),
                return_on_error={}
            )
            self.app.config.update(fetched_config)

        # Fetch secrets
        try:
            self.app.config['credentials'] = credstash.getAllSecrets(
                context={'application': 'second-opinion'},
                credential='second-opinion:*',
                region="us-west-2"
            )
        except:
            self.app.logger.error("Unable to load credentials with credstash")

        # Override the default SECRET_KEY
        self.app.config['SECRET_KEY'] = self.app.config['credentials'][
            'second-opinion:secret-key']

        # Fetch authorization data
        for client_id, authorization_urls in self.app.config.get(
                'OP_AUTHORIZATION_URLS', {}).iteritems():
            authorization_data = self.fetch_and_verify(
                authorization_urls['authorization_data_url'],
                authorization_urls['authorization_data_sig_url'],
                return_on_error={}
            )

            self.app.config['OP_AUTHORIZATION_DATA'][
                client_id] = authorization_data
            self.app.config['OP_USER_INFO'][client_id] =

    def teardown(self, exception):
        pass  # teardown actions

    def get_provider(self, userinfo):
        """Create an OpenID Connect provider using a given user info
        dictionary passed in.

        :param dict userinfo: The user information dictionary associated
        with the client_id of the current request
        :return: An oic provider object
        """
        provider = Provider(
            name=self.app.config['OP_ISSUER'],
            sdb=SessionDB(self.app.config['OP_ISSUER']),
            cdb=self.app.config['OP_CLIENT_DB'],
            authn_broker=self.authn_broker,
            userinfo=UserInfoWithGroups(userinfo),
            authz=AuthzHandling(),
            client_authn=verify_client,
            symkey=None)
        provider.baseurl = self.app.config['OP_ISSUER']
        provider.symkey = rndstr(16)
        provider.keyjar.import_jwks(
            json.loads(
                self.app.config['credentials']['second-opinion:opkeys']),
            issuer='')
        provider.jwks_uri = "{}{}".format(
            provider.baseurl,
            self.app.config['OP_JWKS_ROUTE']
        )
        return provider

    def get_url_or_s3_object(self, url):
        """Fetch the payload of a url from either the web or s3

        :param str url:
        :return: tuple of (success, payload)
        """
        if url.startswith('s3://'):
            client = boto3.client('s3')
            bucket_name = url[5:].split('/')[0]
            key_name = '/'.join(url[5:].split('/')[1:])
            try:
                response = client.get_object(
                    Bucket=bucket_name,
                    Key=key_name
                )
            except Exception as e:
                self.app.logger.error(
                    "Unable to fetch %s : %s" % (url, e))
                return False, ''
            else:
                return True, response['Body'].read()
        else:
            response = requests.get(url)
            if not response.ok:
                self.app.logger.error(
                    "Unable to fetch %s : %s" % (url, response.reason))
            return response.ok, response.content

    @memory.cache
    def fetch_and_verify(
            self, page_url, signature_url,
            authorized_signers=None, return_on_error=False):
        """Fetch content from page_url and a detached signature from
        signature_url, gpg verify that the detached signature is a valid for
        the page and that the signer is in the authorized_signers list of
        fingerprints. Return the page or False.

        :param str page_url: URL of the page to fetch
        :param str signature_url: URL of the detached signature for page_url
        :param list authorized_signers: List of GPG fingerprints that are
        authorized to sign the page or None to indicate that the
        authorized signers should be obtained from the signer map,
        self.app.config['SIGNER_MAP']
        :param return_on_error: value to return on error
        :return: payload for page_url or the content of return_on_error if
        there is a problem with fetching or verification
        """
        page_success, page = self.get_url_or_s3_object(page_url)
        signature_success, signature = self.get_url_or_s3_object(signature_url)
        if not (page_success and signature_success):
            return return_on_error
        if authorized_signers is None:
            matching_authorized_signer_lists = [
                self.app.config['SIGNER_MAP'][url_prefix] for url_prefix
                in self.app.config['SIGNER_MAP']
                if page_url.startswith(url_prefix)]
            if len(matching_authorized_signer_lists) == 0:
                raise Exception(
                    "No matching allowed signers for %s found in signer map" %
                    page_url)
            elif len(matching_authorized_signer_lists) > 0:
                raise Exception(
                    "Multiple matching allowed signer lists found for %s : "
                    "%s" % (page_url, matching_authorized_signer_lists))
            [authorized_signers] = matching_authorized_signer_lists

        signature_filename = os.path.join(
            AWS_LAMBDA_TMP_DIR,
            hashlib.sha256(page).hexdigest()
        )
        with open(signature_filename) as signature_file:
            signature_file.write(signature)
        verification_result = gpg.verify_file(
            file=StringIO.StringIO(page),
            sig_file=signature_file
        )
        if not verification_result.valid:
            self.app.logger.error(
                "Unable to verify %s with detached signature %s : %s" % (
                    page_url, signature_url, verification_result.status
                ))
            return return_on_error
        if verification_result.fingerprint not in authorized_signers:
            self.app.logger.error(
                "Valid signature by %s of %s is not an authorized signer" % (
                    verification_result.fingerprint, page_url
                ))
            return return_on_error
        try:
            result = json.loads(page)
        except ValueError:
            return return_on_error
        else:
            return result

    def get_userinfo(self, client_id=None):
        """Produce an OpenID Connect userinfo data structure for a given
        client_id using that RP's OP_AUTHORIZATION_DATA. The userinfo data
        structure looks like

        {
          "jdoe@example.com": {
            "sub": "",
            "email": "jdoe@example.com",
            "groups": [
              "finance"
            ]
          },
          "user@example.com": {
            "sub": "",
            "email": "user@example.com",
            "groups": [
              "finance"
            ]
          }
        }

        :param str client_id: The client ID of the RP
        :return: Userinfo dictionary
        """
        if client_id is None:
            return {}

        authorization_data = self.app.config['OP_AUTHORIZATION_DATA'].get(
            client_id, {})
        groups = authorization_data.get('groups', {})

        # Create set of flattened list of lists of users in all groups
        users = set(
            [item for sublist in
             [groups[x] for x in groups] for item in
             sublist])
        userinfo = {}
        for user in users:
            userinfo[user] = {
                'sub': 'ad|second-opinion-dev|%s' % user,
                'email': user,
                'groups': self.get_groups_for_user(client_id, user)
            }
        return userinfo

    def get_groups_for_user(self, client_id, user):
        """Given a user return the groups that user is a member of. This
        assumes a structure of OP_AUTHORIZATION_DATA that looks like

        {
          "groups": {
            "finance": [
              "jdoe@example.com",
              "user@exapmle.net"
            ]
          }
        }

        :param str client_id: The client ID of the RP
        :param str user: The username of the user
        :return: A list of group names
        """
        authorization_data = self.app.config['OP_AUTHORIZATION_DATA'].get(
            client_id, {})
        groups = authorization_data.get('groups', {})
        return [x for x in groups if user in groups[x]]


app = Flask(__name__)
op = PyOIDCOP(app)
