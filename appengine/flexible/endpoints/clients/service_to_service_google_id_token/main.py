# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0(the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:  // www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Example of calling a Google Cloud Endpoint API from Google App Engine
Default Service Account using Google ID token."""

import base64
import httplib
import json
import time
import urllib

from googleapiclient import discovery
from google.appengine.api import app_identity
import webapp2

DEFAUTL_SERVICE_ACCOUNT = "yangguan-esp-gce-qs@appspot.gserviceaccount.com"
HOST = "yangguan-esp-gce-qs.appspot.com"
TARGET_AUD = "yangguan-esp-gce-qs@appspot.gserviceaccount.com"


def generate_jwt(account):
    """Generates a signed JSON Web Token using the Google App Engine default
    service account."""
    now = int(time.time())

    header_json = json.dumps({
        "typ": "JWT",
        "alg": "RS256"})

    payload_json = json.dumps({
        "iat": now,
        # expires after one hour.
        "exp": now + 3600,
        # iss is the Google App Engine default service account email.
        "iss": account,
        # scope must match 'audience' for google_id_token in the security
        # configuration in your swagger spec.
        "scope": TARGET_AUD,
        # aud must be Google token endpoints URL.
        "aud": "https://www.googleapis.com/oauth2/v4/token"
    })

    headerAndPayload = '{}.{}'.format(
        base64.urlsafe_b64encode(header_json),
        base64.urlsafe_b64encode(payload_json))

    credentials = AppAssertionCredentials('https://www.googleapis.com/auth/iam')
    http_auth = credentials.authorize(httplib2.Http())
    service = discovery.build(serviceName='iam', version='v1', http=http_auth)
    slist = service.projects().serviceAccounts.signBlob(name=account,
                                                        body={ 'bytesToSign' : base64.b64encode(headerAndPayload)})
    result = slist.execute()
    signature = base64.urlsafe_b64encode(base64.encodestring(res['signature']))

    return headerAndPayload + '.' + signature


def get_id_token(account):
    """Request a Google ID token using a JWT."""
    params = urllib.urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': generate_jwt(account)})
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    conn = httplib.HTTPSConnection("www.googleapis.com")
    conn.request("POST", "/oauth2/v4/token", params, headers)
    res = json.loads(conn.getresponse().read())
    conn.close()
    return res['id_token']


def make_request(token):
    """Makes a request to the auth info endpoint for Google ID token."""
    headers = {'Authorization': 'Bearer {}'.format(token)}
    conn = httplib.HTTPSConnection(HOST)
    conn.request("GET", '/auth/info/googleidtoken', None, headers)
    res = conn.getresponse()
    conn.close()
    return res.read()


class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        token = get_id_token()
        res = make_request(token)
        self.response.write(res)


class JwtPage(webapp2.RequestHandler):
    def get(self):
        account = self.request.get("account", DEFAUTL_SERVICE_ACCOUNT)
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(generate_jwt(account))


class IdTokenPage(webapp2.RequestHandler):
    def get(self):
        account = self.request.get("account", DEFAUTL_SERVICE_ACCOUNT)
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(get_id_token(account))


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/jwt', JwtPage),
    ('/id-token', IdTokenPage),
], debug=True)
