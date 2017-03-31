import duo_web
from credstash import getAllSecrets
import credstash
import string
import logging
from flask import Flask, request, make_response

app = Flask(__name__)
app.debug = True
app.logger.setLevel(logging.DEBUG)

credentials = getAllSecrets(
    context={'application': 'second-opinion'},
    credential='second-opinion:*',
    region="us-west-2"
)

app.logger.info(
    credstash.getSecret('second-opinion:duo:data-host',
                        region="us-west-2",
                        context={'application': 'second-opinion'}))


# TODO : Once I get my pyoidc example
# github.com/gene1wood/pyoidc/oidc_example/simple_op/src/provider/server/server.py
# working, then pull it into this as a handful of routes and functions
# http://flask.pocoo.org/docs/0.12/quickstart/#static-files

@app.route('/')
def index():
    return "hi"


@app.route('/favicon.ico')
def favicon():
    return make_response("404", 404)


@app.route('/user/<email>',
           methods=['GET', 'POST'])
def user(email):
    if request.method == 'POST':
        authenticated_username = duo_web.verify_response(
            credentials['second-opinion:duo:ikey'],
            credentials['second-opinion:duo:skey'],
            credentials['second-opinion:duo:akey'],
            request.form['sig_response']
        )
        if authenticated_username:
            return "<h1>Success %s</h1>" % authenticated_username
    elif request.method == 'GET':
        sign_function = duo_web.sign_request
        sig_request = sign_function(
            credentials['second-opinion:duo:ikey'],
            credentials['second-opinion:duo:skey'],
            credentials['second-opinion:duo:akey'],
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
            data_host=credentials['second-opinion:duo:data-host'],
            sig_request=sig_request
        ).encode('ascii', 'ignore')
        return body
