import os

from urllib import request

from flask import Flask, redirect, url_for, session, render_template_string, request, render_template

from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token

import json

#import sqlite3

app = Flask(__name__)
app.secret_key = 'ace0fba5e1458b6e9b795d59e03b32b44556bf7fa55e26c160594320f532154422deadbeef'
app.config['SESSION_COOKIE_NAME'] = 'oidc_tester_session'
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

OIDC_CLIENT_SECRET = 'THISWASNEVERAREALCLIENTSECRET'
OIDC_CLIENT_ID = 'THISWASNEVERAREALCLIENTID'
OIDC_DISCOVERY_URL = 'THISWASNEVERAREALDISCOVERYURL'


# Initialize OAuth and configure the OIDC provider
oauth = OAuth(app)
oidc = None

def init_oidc_client(oidc_client_id, oidc_client_secret, oidc_discovery_url):
    global oidc
    oidc = oauth.register(
        name = 'oidc',
        client_id = oidc_client_id,
        client_secret = oidc_client_secret,
        server_metadata_url = oidc_discovery_url,
        client_kwargs={'scope': 'openid profile email',
                       'verify': False},
    )


#context = (r'cert.pem', r'key.pem')
#ext_cert = r'cfs_new.pem'

"""
Let's talk about routing with Flask before we go any further so that I don't lose anyone in the plot.

/ (main.html)
  - /oidc_client (oidc.client.html)
    - /auth_code_flow (auth_code_flow.html)
      - /oidc_executor (POST, redirects to /login)
        - /login (Redirects us to the appropriate space to authenticate, gets us an authorization code)
          - /auth (Gets us an access token, redirects to /results with the scopes we return)
    - /results (Shows us the relevant scopes we requested, demonstrating appropriate connectivity)
"""
@app.route('/')
def start():
    return render_template("main.html")

@app.route('/oidc_client')
def oidc_client():
    return render_template("oidc_client.html")

@app.route('/auth_code_flow')
def auth_code_flow():
    return render_template("auth_code_flow.html")

@app.route('/oidc_executor', methods=['POST'])
def executor():
    if request.method == 'POST':
        oidc_client_secret = request.form.get('Editbox1')
        oidc_client_id = request.form.get('Editbox2')
        oidc_discovery_url = request.form.get('Editbox3')

        if oidc_client_secret and oidc_client_id and oidc_discovery_url:
            init_oidc_client(oidc_client_id, oidc_client_secret, oidc_discovery_url)
            return redirect(url_for('login'))

        else:
            redirect(url_for("auth_code_flow"))
    else:
        redirect(url_for("auth_code_flow"))

@app.route('/login')
def login():
    global oidc
    if oidc:
        nonce = generate_token()
        session['oidc_nonce'] = nonce
        redirect_uri = url_for('auth', _external=True)
        return oidc.authorize_redirect(redirect_uri, nonce=nonce)
    else:
        return redirect('/fail')

@app.route('/auth')
def auth():
    global oidc
    if oidc:
        token = oidc.authorize_access_token()
        session['token'] = token
        nonce = session.pop('oidc_nonce', None)
        user_info = oidc.parse_id_token(token, nonce=nonce)
        session['user'] = user_info
        return redirect('/results')
    else:
        return redirect('/fail')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/fail')
def failure():
    return render_template_string("""
                <h1>THIS IS A FAIL</h1>
            """)

@app.route('/results')
def results():
    user_info = session.get('user')
    try:
        token = session['token']
    except KeyError:
            return '<a href="/login">Login with OIDC</a>'
    except UnboundLocalError:
            return '<a href="/login">Login with OIDC</a>'
    if user_info:
        displayed_user = None
        if token:
            displayed_user = user_info['email']
        pretty_json = json.dumps(token, indent=2, sort_keys=True)
        return render_template_string("""
            <h1>You're logged in!</h1>
            {% if displayed_user %}
                <p><strong>Welcome, User </strong> {{ displayed_user }}<strong>!</strong></p>
            {% else %}
                <p><em>User not found in token.</em></p>
            {% endif %}
            <h2>Full Token</h2>
            <pre style="background:#f4f4f4; padding:1em; border-radius:5px;">{{ json_data }}</pre>
        """, displayed_user=displayed_user, json_data=pretty_json)
    return '<a href="/login">Login with OIDC</a>'


if __name__ == '__main__':
    #app.run(host="0.0.0.0", port=443, debug=True, ssl_context=(context))
    if os.path.exists('data.db'):
        # Delete the existing database file
        os.remove('data.db')

    app.run(host="0.0.0.0", port=8080, debug=True)