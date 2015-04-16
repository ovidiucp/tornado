#!/usr/bin/env python
#
# Author: Ovidiu Predescu
# Date: April 16, 2015
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

#
# To use this make sure you have a project created in Google's Developer Console
#
# https://console.developers.google.com
#
# Under "APIs & auth" menu entry, click "APIs", then select and enable
# the Google+ API.
#
# Under "Credentials", look at the OAuth section. If you don't have a
# "Client ID for web application", create one.
#
# This will generate a "Client ID" and a "Client secret". Make a note
# of them as you'll need them later on.
#
# Click the "Edit settings" and add in the "Authorized redirect URIs"
# the following URL, and click "Update"
#
# http://localhost:8888/auth/login
#
# If you change the port in the command line, make sure you use that
# port instead of 8888.
#
# Now run the program like this:
#
# python google.py --google_client_id="..." --google_client_secret="..."
#
# using the values you made a note of as described above.

import tornado.auth
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.gen
from tornado.auth import GoogleOAuth2Mixin
from tornado import httpclient

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)
define("google_client_id", type=str, default=None,
       help="Your Google Client ID")
define("google_client_secret", type=str, default=None,
       help="Your Google Client secret")

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/auth/login", AuthHandler),
            (r"/auth/logout", LogoutHandler),
        ]
        settings = dict(
            cookie_secret="ze507?(wBk(j\aYB4cIi(01D#AttyWsOB*fEJ<-VJ:Sd9Tqa/E/",
            login_url="/auth/login",
            redirect_uri="http://localhost:8888/auth/login",
            google_oauth = dict(
                key = options.google_client_id,
                secret = options.google_client_secret
            )
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        print 'current_user', self.current_user
        name = tornado.escape.xhtml_escape(self.current_user["name"])
        picture = self.current_user.get('picture', None)
        if picture:
            self.write("<img src='" + picture + "' width='96' height='96'>")
        self.write("<br><br>Hello, " + name)
        self.write("<br><br><a href=\"/auth/logout\">Log out</a>")


class AuthHandler(BaseHandler, GoogleOAuth2Mixin):
    @tornado.gen.coroutine
    def get(self):
        if self.get_argument("code", None):
            response = yield self.get_authenticated_user(
                redirect_uri=self.settings['redirect_uri'],
                code=self.get_argument('code'))
            access_token = response['access_token']
            http_client = self.get_auth_http_client()
            url = 'https://www.googleapis.com/oauth2/v1/userinfo?access_token='
            response = yield http_client.fetch(url + access_token)
            print 'Got response:', response.body
            self.set_secure_cookie("user", response.body)
            self.set_secure_cookie("access_token", access_token)
            self.redirect('/')
        elif self.get_argument('error', None):
            self.write("Access denied. <br><br><a href='/auth/login'>Login</a>")
        else:
            yield self.authorize_redirect(
                redirect_uri=self.settings['redirect_uri'],
                client_id=self.settings['google_oauth']['key'],
                scope=['email', 'profile', 'openid'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})

class LogoutHandler(BaseHandler):
    @tornado.gen.coroutine
    def get(self):
        access_token = self.get_secure_cookie("access_token")
        if access_token:
            revokeUrl = 'https://accounts.google.com/o/oauth2/revoke?token='
            http_client = httpclient.AsyncHTTPClient()
            response = yield http_client.fetch(revokeUrl + access_token)
        self.clear_all_cookies()
        self.write("<br><br>You are logged out.<br><br>"\
                   "<a href=\"/auth/login\">Login</a>")

def main():
    tornado.options.parse_command_line()
    if not (options.google_client_id and options.google_client_secret):
        print("--google_client_id and --google_client_secret must be set")
        return

    print 'Running server on port', options.port
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
