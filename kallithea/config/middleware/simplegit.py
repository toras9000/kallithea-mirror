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
kallithea.config.middleware.simplegit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SimpleGit middleware for handling Git protocol requests (push/clone etc.)
It's implemented with basic auth function

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 28, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.

"""


import logging
import re

from kallithea.config.middleware.pygrack import make_wsgi_app
from kallithea.controllers import base
from kallithea.lib import hooks


log = logging.getLogger(__name__)


GIT_PROTO_PAT = re.compile(r'^/(.+)/(info/refs|git-upload-pack|git-receive-pack)$')


cmd_mapping = {
    'git-receive-pack': 'push',
    'git-upload-pack': 'pull',
}


class SimpleGit(base.BaseVCSController):

    scm_alias = 'git'

    @classmethod
    def parse_request(cls, environ):
        path_info = base.get_path_info(environ)
        m = GIT_PROTO_PAT.match(path_info)
        if m is None:
            return None

        class parsed_request(object):
            # See https://git-scm.com/book/en/v2/Git-Internals-Transfer-Protocols#_the_smart_protocol
            repo_name = m.group(1).rstrip('/')
            cmd = m.group(2)

            query_string = environ['QUERY_STRING']
            if cmd == 'info/refs' and query_string.startswith('service='):
                service = query_string.split('=', 1)[1]
                action = cmd_mapping.get(service)
            else:
                service = None
                action = cmd_mapping.get(cmd)

        return parsed_request

    def _make_app(self, parsed_request):
        """
        Return a pygrack wsgi application.
        """
        pygrack_app = make_wsgi_app(parsed_request.repo_name, self.basepath)

        def wrapper_app(environ, start_response):
            if (parsed_request.cmd == 'info/refs' and
                parsed_request.service == 'git-upload-pack'
            ):
                # Run hooks like Mercurial outgoing.kallithea_pull_action does
                hooks.log_pull_action()
            # Note: push hooks are handled by post-receive hook

            return pygrack_app(environ, start_response)

        return wrapper_app
