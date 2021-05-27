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
kallithea.config.middleware.https_fixup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

middleware to handle https correctly

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: May 23, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import kallithea
from kallithea.lib.utils2 import asbool


class HttpsFixup(object):

    def __init__(self, app, config):
        self.application = app
        self.config = config

    def __call__(self, environ, start_response):
        self.__fixup(environ)
        debug = asbool(self.config.get('debug'))
        is_ssl = environ['wsgi.url_scheme'] == 'https'

        def custom_start_response(status, headers, exc_info=None):
            if is_ssl and asbool(self.config.get('use_htsts')) and not debug:
                headers.append(('Strict-Transport-Security',
                                'max-age=8640000; includeSubDomains'))
            return start_response(status, headers, exc_info)

        return self.application(environ, custom_start_response)

    def __fixup(self, environ):
        """
        Function to fixup the environ as needed. In order to use this
        middleware you should set this header inside your
        proxy ie. nginx, apache etc.
        """
        proto = None

        # if we have force, just override
        if asbool(self.config.get('force_https')):
            proto = 'https'
        else:
            # get protocol from configured WSGI environment variable
            url_scheme_variable = kallithea.CONFIG.get('url_scheme_variable')
            if url_scheme_variable:
                proto = environ.get(url_scheme_variable)

        if proto:
            environ['wsgi._org_proto'] = environ.get('wsgi.url_scheme')
            environ['wsgi.url_scheme'] = proto
