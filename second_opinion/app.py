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
from oic.utils.sdb import create_session_db
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
import errno
import shelve
import copy

AWS_LAMBDA_TMP_DIR = '/tmp/second-opinion'
SIGNER_MAP_URL = (
    's3://infosec-internal-data/second-opinion/prod/signer-map.json')
SIGNER_MAP_SIG_URL = (
    's3://infosec-internal-data/second-opinion/prod/signer-map.json.sig')
SIGNING_ROOT_AUTHORITY_FINGERPRINTS = {
    SIGNER_MAP_URL: ['85914504D0BFA220E93A6D25B40E5BDC92377335']
}
SIGNING_ROOT_AUTHORITY_PUBLIC_KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\n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\n=gXVD\n-----END PGP PUBLIC KEY BLOCK-----"

try:
    os.makedirs(AWS_LAMBDA_TMP_DIR, 0700)
except OSError as e:
    if e.errno != errno.EEXIST or not os.path.isdir(AWS_LAMBDA_TMP_DIR):
        raise
memory = Memory(cachedir=AWS_LAMBDA_TMP_DIR)
gpg = gnupg.GPG(homedir=AWS_LAMBDA_TMP_DIR, verbose=False)


def get_url_or_s3_object(url):
    """Fetch the payload of a url from either the web or s3

    :param str url:
    :return: tuple of (success, payload)
    """
    # TODO : Add argument to pass s3 region optionally so that this s3 fetch
    #  can skip the redirect from the local region to the region of the bucket
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
            app.logger.error(
                "Unable to fetch %s : %s" % (url, e))
            return False, ''
        else:
            return True, response['Body'].read()
    else:
        response = requests.get(url)
        if not response.ok:
            app.logger.error(
                "Unable to fetch %s : %s" % (url, response.reason))
        return response.ok, response.content


@memory.cache
def fetch_and_verify(page_url, signature_url, signer_map):
    """Fetch content from page_url and a detached signature from
    signature_url, gpg verify that the detached signature is valid for
    the page and that the signer is in the signer_map. Return the page or
    False.

    :param str page_url: URL of the page to fetch
    :param str signature_url: URL of the detached signature for page_url
    :param dict signer_map: Dictionary where each key is a URL and each
    value is a list of GPG fingerprints that are
    authorized to sign the page at that URL
    :return: payload for page_url or the content of return_on_error if
    there is a problem with fetching or verification
    """
    page_success, page = get_url_or_s3_object(page_url)
    signature_success, signature = get_url_or_s3_object(signature_url)
    if not (page_success and signature_success):
        return False

    matching_authorized_signer_lists = [
        signer_map[url_prefix] for url_prefix
        in signer_map
        if page_url.startswith(url_prefix)]
    if len(matching_authorized_signer_lists) == 0:
        raise Exception(
            "No matching allowed signers for %s found in signer map" %
            page_url)
    elif len(matching_authorized_signer_lists) > 1:
        raise Exception(
            "Multiple matching allowed signer lists found for %s : "
            "%s" % (page_url, matching_authorized_signer_lists))
    [authorized_signers] = matching_authorized_signer_lists
    signature_filename = os.path.join(
        AWS_LAMBDA_TMP_DIR,
        hashlib.sha256(page).hexdigest()
    )
    with open(signature_filename, 'w') as signature_file:
        signature_file.write(signature)
    import subprocess
    # app.logger.debug("gpg version is %s" %
    #                  subprocess.check_output(["/usr/bin/gpg2", "--version"]))
    verification_result = gpg.verify_file(
        file=StringIO.StringIO(page),
        sig_file=signature_filename
    )
    if not verification_result.valid:
        app.logger.error(
            "Unable to verify %s with detached signature %s : %s" % (
                page_url, signature_url, verification_result.status
            ))
        return False
    if verification_result.fingerprint not in authorized_signers:
        app.logger.error(
            "Valid signature by %s of %s is not an authorized signer" % (
                verification_result.fingerprint, page_url
            ))
        return False
    try:
        result = json.loads(page)
    except ValueError:
        return False
    else:
        return result


class ShelfWrapper(object):
    def __init__(self, filename):
        self.filename = filename

    def keys(self):
        db = self._reopen_database()
        return db.keys()

    def __len__(self):
        db = self._reopen_database()
        return db.__len__()

    def has_key(self, key):
        return (key if type(key) == str else key.encode('utf8')) in self

    def __contains__(self, key):
        db = self._reopen_database()
        return db.__contains__(key if type(key) == str else key.encode('utf8'))

    def get(self, key, default=None):
        db = self._reopen_database()
        return db.get(key if type(key) == str else key.encode('utf8'), default)

    def __getitem__(self, key):
        db = self._reopen_database()
        return db.__getitem__(key if type(key) == str else key.encode('utf8'))

    def __setitem__(self, key, value):
        db = self._reopen_database()
        db.__setitem__(key if type(key) == str else key.encode('utf8'), value)

    def __delitem__(self, key):
        db = self._reopen_database()
        db.__delitem__(key if type(key) == str else key.encode('utf8'))

    def _reopen_database(self):
        return shelve.open(self.filename, writeback=True)


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

        logging.debug(
            "app.py UserInfoWithGroups.filter: userinfo, user_info_claims = "
            "%s, %s" % (userinfo, user_info_claims))
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
            logging.debug(
                "app.py UserInfoWithGroups.filter: result = "
                "%s" % result)
            return result


class DuoAuthnMethod(UserAuthnMethod):
    def __init__(self, srv, app, ttl=5, **kwargs):
        UserAuthnMethod.__init__(self, srv, ttl)
        # super(DuoAuthnMethod, self).__init__(None)
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
        self.app.logger.debug(
            "Result of Duo verify_response of '%s' with ikey %s : %s" %
            (request.form['sig_response'],
             self.app.config['credentials']['second-opinion:duo:ikey'],
             authenticated_username))

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
                self.app.logger.debug(
                    "Setting cookie %s to %s with args %s" % (
                        cookie_name,
                        cookie[cookie_name].value,
                        {k: v for k, v
                         in cookie[cookie_name].iteritems()
                         if k in ['key',
                                  'max_age',
                                  'expires',
                                  'path',
                                  'domain',
                                  'secure',
                                  'httponly']
                         and len(cookie[cookie_name][k]) > 0}
                    ))
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
        self.sdb = ShelfWrapper('/tmp/session_db')
        self.provider = None
        self.authn_broker = AuthnBroker()
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

        # TODO : Consider if this flimsy persistence is good enough. If the
        # lambda host changes between calls this session persistence will fail

        # /duo/verify
        def verify():
            return DuoAuthnMethod(self.provider, self.app).verify()

        # /.well-known/jwks.json
        def jwks():
            provider = self.get_provider(
                self.get_userinfo(request.args.get('client_id', None)))
            return jsonify(provider.keyjar.export_jwks(private=False))

        # /authorization
        def authorization():
            a = self.provider.authorization_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )
            self.app.logger.debug("Result of authorization endpoint : %s" % a)
            return a

        # /token
        def token():
            return self.provider.token_endpoint(
                request=request.values.to_dict(),
                dtype='dict',
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /userinfo
        def userinfo():
            return self.provider.userinfo_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; '),
                authn=request.headers.get('Authorization', '')
            )

        # /registration
        def registration():
            return self.provider.registration_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /end_session
        def end_session():
            return self.provider.endsession_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /.well-known/openid-configuration
        def providerinfo():
            return self.provider.providerinfo_endpoint(
                request=request.values.to_dict(),
                cookie=SimpleCookie(request.cookies).output(
                    header='', sep='; ')
            )

        # /.well-known/webfinger
        def webfinger():
            if request.values["rel"] == OIC_ISSUER:
                wf = WebFinger()
                return Response(
                    wf.response(
                        request.values["resource"],
                        self.provider.baseurl
                    )), [("Content-Type", "application/jrd+json")]
            else:
                return BadRequest("Incorrect webfinger.")

        # /static
        # Served automatically from the static directory
        # http://flask.pocoo.org/docs/0.12/quickstart/#static-files

        # /clear-cache
        @self.app.route("/clear-cache")
        def clear_cache():
            memory.clear()
            return "Success"

        self.app.add_url_rule(
            rule=self.app.config['OP_DUO_VERIFY_ROUTE'],
            endpoint='verify',
            view_func=self.call_view_func(verify),
            # TODO : should this instead be make_auth_verify(duo_auth_instance.verify)?
            methods=['POST'])
        self.app.add_url_rule(
            rule=self.app.config['OP_JWKS_ROUTE'],
            endpoint='jwks',
            view_func=self.call_view_func(jwks))
        self.app.add_url_rule(
            rule="/{}".format(AuthorizationEndpoint.etype),
            endpoint='authorization',
            view_func=self.call_view_func(authorization),
            methods=['GET', 'POST'])
        self.app.add_url_rule(
            rule="/{}".format(TokenEndpoint.etype),
            endpoint='token',
            view_func=self.call_view_func(token),
            methods=['POST'])
        self.app.add_url_rule(
            rule="/{}".format(UserinfoEndpoint.etype),
            endpoint='userinfo',
            view_func=self.call_view_func(userinfo))
        self.app.add_url_rule(
            rule="/{}".format(RegistrationEndpoint.etype),
            endpoint='registration',
            view_func=self.call_view_func(registration))
        self.app.add_url_rule(
            rule="/{}".format(EndSessionEndpoint.etype),
            endpoint='end_session',
            view_func=self.call_view_func(end_session))
        self.app.add_url_rule(
            rule="/.well-known/openid-configuration",
            endpoint='providerinfo',
            view_func=self.call_view_func(providerinfo))
        self.app.add_url_rule(
            rule="/.well-known/webfinger",
            endpoint='webfinger',
            view_func=self.call_view_func(webfinger))

    def load_config(self):
        """Build the configuration by overlaying defaults with environment
        variables and with config drawn from the CONFIG_URL page. Add in
        secrets from credstash. Add in authorization data for the users of
        each relying party.

        :return:
        """

        # Establish default configuration values
        defaults = {
            'DEBUG': True,
            'OP_ISSUER': 'https://second-opinion.security.allizom.org',
            'OP_JWKS_ROUTE': '/.well-known/jwks.json',
            'OP_DUO_VERIFY_ROUTE': '/duo/verify',
            'OP_USERINFO': {},
            'OP_CLIENT_DB': {},
            'OP_AUTHORIZATION_DATA': {},
            'SYMKEY': '0123456789012345',
            'SESSION_KEY': "a"*64,
            'DEFAULT_TOKEN_SECRET_KEY': 'bbccbbcc'
        }

        # TODO : Move these secrets into credstash

        app.config.update(defaults)

        # Override the defaults with any environment variables
        for v in [x for x in os.environ if x in defaults]:
            self.app.config[v] = os.environ.get(v)

        # Fetch the signer map
        gpg.import_keys(SIGNING_ROOT_AUTHORITY_PUBLIC_KEY)
        signer_map = fetch_and_verify(
            SIGNER_MAP_URL,
            SIGNER_MAP_SIG_URL,
            SIGNING_ROOT_AUTHORITY_FINGERPRINTS
        ) or {}
        self.app.config['SIGNER_MAP'] = (
            signer_map['signer_map'] if 'signer_map' in signer_map else {})
        if ('public_keys' in signer_map
                and type(signer_map['public_keys']) == list):
            for key in signer_map['public_keys']:
                gpg.import_keys(key)

        # Fetch the hosted config
        if 'CONFIG_URL' in os.environ:
            fetched_config = fetch_and_verify(
                os.environ.get('CONFIG_URL'),
                os.environ.get('CONFIG_SIG_URL'),
                self.app.config['SIGNER_MAP']
            ) or {}
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

        # Add client secrets to config client DB
        client_secret_key_prefix = 'second-opinion:client_secret:'
        for key in [x for x in self.app.config['credentials'] if
                    x.startswith(client_secret_key_prefix)]:
            client_id = key[len(client_secret_key_prefix):]
            if client_id in self.app.config['OP_CLIENT_DB']:
                self.app.config['OP_CLIENT_DB'][client_id]['client_secret'] \
                    = self.app.config['credentials'][key]

        # Override the default SECRET_KEY
        self.app.config['SECRET_KEY'] = self.app.config['credentials'][
            'second-opinion:secret-key']

        # Fetch authorization data for all RPs
        # TODO : Consider how durable the cached versions of these files are
        #  and consider the problem if they're not durable of second opinion
        #  having to go out and fetch a bunch of different files (every
        # clients authorization data) each time it's called. If we know the
        # client_id on every call to second opinion where this config is
        # needed (which I'm not sure we do), we could only fetch the data
        # for that specific client into the config for that call.
        for client_id, authorization_urls in self.app.config.get(
                'OP_AUTHORIZATION_URLS', {}).iteritems():
            app.logger.debug("authorization_urls is %s : %s" %
                             (client_id, authorization_urls))
            client_signer_map = fetch_and_verify(
                authorization_urls['signer_map_url'],
                authorization_urls['signer_map_sig_url'],
                self.app.config['SIGNER_MAP']
            ) or {}

            if 'public_keys' in client_signer_map and type(
                    client_signer_map['public_keys']) == list:
                for key in client_signer_map['public_keys']:
                    gpg.import_keys(key)

            authorization_data = fetch_and_verify(
                authorization_urls['authorization_data_url'],
                authorization_urls['authorization_data_sig_url'],
                client_signer_map['signer_map']
            ) or {}

            self.app.config['OP_AUTHORIZATION_DATA'][
                client_id] = authorization_data

    def teardown(self, exception):
        pass  # teardown actions

    def get_provider(self, userinfo):
        """Create an OpenID Connect provider using a given user info
        dictionary passed in.

        :param dict userinfo: The user information dictionary associated
        with the client_id of the current request
        :return: An oic provider object
        """
        app.logger.debug("app.py PyOIDCOP.get_provider userinfo = %s" %
                         userinfo)

        duo_auth_instance = DuoAuthnMethod(
            None, self.app)  # TODO : Why are we passing None as `srv`?
        # This is a chicken egg problem
        self.authn_broker.add("duo", duo_auth_instance)

        provider = Provider(
            name=self.app.config['OP_ISSUER'],
            sdb=create_session_db(
                self.app.config['OP_ISSUER'],
                self.app.config['SESSION_KEY'],
                password=self.app.config['DEFAULT_TOKEN_SECRET_KEY'],
                db=self.sdb),
            cdb=self.app.config['OP_CLIENT_DB'],
            authn_broker=self.authn_broker,
            userinfo=UserInfoWithGroups(userinfo),
            authz=AuthzHandling(),
            client_authn=verify_client,
            symkey=self.app.config['SYMKEY'])
        provider.baseurl = self.app.config['OP_ISSUER']
        provider.keyjar.import_jwks(
            json.loads(
                self.app.config['credentials']['second-opinion:opkeys']),
            issuer='')
        provider.jwks_uri = "{}{}".format(
            provider.baseurl,
            self.app.config['OP_JWKS_ROUTE']
        )
        return provider

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

    def call_view_func(self, view_func):
        self.provider = self.get_provider(
            self.get_userinfo(request.args.get('client_id', None)))
        return view_func()

app = Flask(__name__)
op = PyOIDCOP(app)
