# -*- coding: utf-8 -*-
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
kallithea.lib.auth_modules.auth_crowd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Kallithea authentication plugin for Atlassian CROWD

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Created on Nov 17, 2012
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import base64
import logging
import urllib.parse
import urllib.request

from kallithea.lib import auth_modules, ext_json
from kallithea.lib.compat import hybrid_property
from kallithea.lib.utils2 import ascii_bytes, ascii_str, safe_bytes


log = logging.getLogger(__name__)


class CrowdServer(object):
    def __init__(self, *args, **kwargs):
        """
        Create a new CrowdServer object that points to IP/Address 'host',
        on the given port, and using the given method (https/http). user and
        passwd can be set here or with set_credentials. If unspecified,
        "version" defaults to "latest".

        example::

            cserver = CrowdServer(host="127.0.0.1",
                                  port="8095",
                                  user="some_app",
                                  passwd="some_passwd",
                                  version="1")
        """
        if "port" not in kwargs:
            kwargs["port"] = "8095"
        self._logger = kwargs.get("logger", logging.getLogger(__name__))
        self._uri = "%s://%s:%s/crowd" % (kwargs.get("method", "http"),
                                    kwargs.get("host", "127.0.0.1"),
                                    kwargs.get("port", "8095"))
        self.set_credentials(kwargs.get("user", ""),
                             kwargs.get("passwd", ""))
        self._version = kwargs.get("version", "latest")
        self._url_list = None
        self._appname = "crowd"

    def set_credentials(self, user, passwd):
        self.user = user
        self.passwd = passwd
        self._make_opener()

    def _make_opener(self):
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self._uri, self.user, self.passwd)
        handler = urllib.request.HTTPBasicAuthHandler(mgr)
        self.opener = urllib.request.build_opener(handler)

    def _request(self, url, body=None):
        _headers = {"Content-type": "application/json",
                    "Accept": "application/json"}
        if self.user and self.passwd:
            authstring = ascii_str(base64.b64encode(safe_bytes("%s:%s" % (self.user, self.passwd))))
            _headers["Authorization"] = "Basic %s" % authstring
        log.debug("Sent to crowd at %s:\nHeaders: %s\nBody:\n%s", url, _headers, body)
        req = urllib.request.Request(url, body, _headers)

        global msg
        msg = None
        try:
            rdoc = self.opener.open(req)
            msg = rdoc.read()
            rval = ext_json.loads(msg)
            rval["status"] = True
        except Exception as e:
            rval = {"status": False,
                    "body": body,
                    "error": "%s\n%r" % (e, msg)}
        return rval

    def user_auth(self, username, password):
        """Authenticate a user against crowd. Returns brief information about
        the user."""
        url = ("%s/rest/usermanagement/%s/authentication?username=%s"
               % (self._uri, self._version, urllib.parse.quote(username)))
        body = ascii_bytes(ext_json.dumps({"value": password}))
        return self._request(url, body)

    def user_groups(self, username):
        """Retrieve a list of groups to which this user belongs."""
        url = ("%s/rest/usermanagement/%s/user/group/nested?username=%s"
               % (self._uri, self._version, urllib.parse.quote(username)))
        return self._request(url)


class KallitheaAuthPlugin(auth_modules.KallitheaExternalAuthPlugin):
    def __init__(self):
        self._protocol_values = ["http", "https"]

    @hybrid_property
    def name(self):
        return "crowd"

    def settings(self):
        settings = [
            {
                "name": "method",
                "validator": self.validators.OneOf(self._protocol_values),
                "type": "select",
                "values": self._protocol_values,
                "description": "The protocol used to connect to the Atlassian CROWD server.",
                "formname": "Protocol"
            },
            {
                "name": "host",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "string",
                "description": "The FQDN or IP of the Atlassian CROWD Server",
                "default": "127.0.0.1",
                "formname": "Host"
            },
            {
                "name": "port",
                "validator": self.validators.Number(strip=True),
                "type": "int",
                "description": "The Port in use by the Atlassian CROWD Server",
                "default": 8095,
                "formname": "Port"
            },
            {
                "name": "app_name",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "string",
                "description": "The Application Name to authenticate to CROWD",
                "default": "",
                "formname": "Application Name"
            },
            {
                "name": "app_password",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "string",
                "description": "The password to authenticate to CROWD",
                "default": "",
                "formname": "Application Password"
            },
            {
                "name": "admin_groups",
                "validator": self.validators.UnicodeString(strip=True),
                "type": "string",
                "description": "A comma separated list of group names that identify users as Kallithea Administrators",
                "formname": "Admin Groups"
            }
        ]
        return settings

    def use_fake_password(self):
        return True

    def auth(self, userobj, username, password, settings, **kwargs):
        """
        Given a user object (which may be null), username, a plaintext password,
        and a settings object (containing all the keys needed as listed in settings()),
        authenticate this user's login attempt.

        Return None on failure. On success, return a dictionary of the form:

            see: KallitheaAuthPluginBase.auth_func_attrs
        This is later validated for correctness
        """
        if not username or not password:
            log.debug('Empty username or password skipping...')
            return None

        log.debug("Crowd settings: %s", settings)
        server = CrowdServer(**settings)
        server.set_credentials(settings["app_name"], settings["app_password"])
        crowd_user = server.user_auth(username, password)
        log.debug("Crowd returned: %s", crowd_user)
        if not crowd_user["status"]:
            log.error('Crowd authentication as %s returned no status', username)
            return None

        if not crowd_user.get('active'):
            log.error('Crowd authentication as %s returned in-active user', username)
            return None

        res = server.user_groups(crowd_user["name"])
        log.debug("Crowd groups: %s", res)
        crowd_user["groups"] = [x["name"] for x in res["groups"]]

        # old attrs fetched from Kallithea database
        admin = getattr(userobj, 'admin', False)
        email = getattr(userobj, 'email', '')
        firstname = getattr(userobj, 'firstname', '')
        lastname = getattr(userobj, 'lastname', '')

        user_data = {
            'username': crowd_user["name"] or username,
            'firstname': crowd_user["first-name"] or firstname,
            'lastname': crowd_user["last-name"] or lastname,
            'groups': crowd_user["groups"],
            'email': crowd_user["email"] or email,
            'admin': admin,
            'extern_name': crowd_user["name"],
        }

        # set an admin if we're in admin_groups of crowd
        for group in settings["admin_groups"].split(","):
            if group in user_data["groups"]:
                user_data["admin"] = True
        log.debug("Final crowd user object: %s", user_data)
        log.info('user %s authenticated correctly', user_data['username'])
        return user_data

    def get_managed_fields(self):
        return ['username', 'firstname', 'lastname', 'email', 'password']
