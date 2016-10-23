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

"""Example of calling a Google Cloud Endpoint API with a JWT signed by a
Service Account."""

import base64
import httplib
import urllib
import json
import time

from googleapiclient.discovery import build
import httplib2
from oauth2client.contrib.appengine import AppAssertionCredentials
from oauth2client.client import GoogleCredentials
import webapp2

SERVICE_ACCOUNT_EMAIL = "serviceaccount@yangguan-esp-gce-qs.iam.gserviceaccount.com"
HOST = "YOUR-SERVER-PROJECT-ID.appspot.com"
SERVICE_ACCOUNT = \
  "projects/yangguan-esp-gce-qs/serviceAccounts/" + SERVICE_ACCOUNT_EMAIL


def generate_jwt():
    """Generates a signed JSON Web Token using a service account."""
    credentials = GoogleCredentials.get_application_default()
    service = build(serviceName='iam', version='v1', credentials=credentials)

    now = int(time.time())

    header_json = json.dumps({
        "typ": "JWT",
        "alg": "RS256"})

    payload_json = json.dumps({
        'iat': now,
        # expires after one hour.
        "exp": now + 3600,
        # iss is the service account email.
        'iss': SERVICE_ACCOUNT_EMAIL,
        'scope': "yangguan-esp-gce-qs@appspot.gserviceaccount.com",
        # aud must match 'audience' in the security configuration in your
        # swagger spec.It can be any string.
        'aud': 'https://www.googleapis.com/oauth2/v4/token'
    })

    headerAndPayload = '{}.{}'.format(
        base64.urlsafe_b64encode(header_json),
        base64.urlsafe_b64encode(payload_json))
    slist = service.projects().serviceAccounts().signBlob(
        name=SERVICE_ACCOUNT,
        body={'bytesToSign': base64.b64encode(headerAndPayload)})
    res = slist.execute()
    signature = base64.urlsafe_b64encode(
        base64.decodestring(res['signature']))
    signed_jwt = '{}.{}'.format(headerAndPayload, signature)

    return signed_jwt


def get_id_token():
    """Request a Google ID token using a JWT."""
    params = urllib.urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': generate_jwt()})
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    conn = httplib.HTTPSConnection("www.googleapis.com")
    conn.request("POST", "/oauth2/v4/token", params, headers)
    response = conn.getresponse()
    if response.status != 200:
        return '{} {}\n{}'.format(response.status, response.reason,
                                  response.read())

    res = json.loads(response.read())
    conn.close()
    return res['id_token']


def make_request(signed_jwt):
    """Makes a request to the auth info endpoint for Google JWTs."""
    headers = {'Authorization': 'Bearer {}'.format(signed_jwt)}
    conn = httplib.HTTPSConnection(HOST)
    conn.request("GET", '/auth/info/googlejwt', None, headers)
    res = conn.getresponse()
    conn.close()
    return res.read()


class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        signed_jwt = generate_jwt()
        res = make_request(signed_jwt)
        self.response.write(res)


class TokenPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        signed_jwt = generate_jwt()
        self.response.write(signed_jwt)


class IdTokenPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(get_id_token())


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/token', TokenPage),
    ('/id-token', IdTokenPage),
], debug=True)
