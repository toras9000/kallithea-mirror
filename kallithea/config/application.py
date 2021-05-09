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
"""WSGI middleware initialization for the Kallithea application."""

from kallithea.config.app_cfg import base_config
from kallithea.config.middleware.https_fixup import HttpsFixup
from kallithea.config.middleware.permanent_repo_url import PermanentRepoUrl
from kallithea.config.middleware.simplegit import SimpleGit
from kallithea.config.middleware.simplehg import SimpleHg
from kallithea.config.middleware.wrapper import RequestWrapper
from kallithea.lib.utils2 import asbool


__all__ = ['make_app']


def wrap_app(app):
    """Wrap the TG WSGI application in Kallithea middleware"""
    config = app.config

    # we want our low level middleware to get to the request ASAP. We don't
    # need any stack middleware in them - especially no StatusCodeRedirect buffering
    app = SimpleHg(app, config)
    app = SimpleGit(app, config)

    # Enable https redirects based on HTTP_X_URL_SCHEME set by proxy
    if any(asbool(config.get(x)) for x in ['url_scheme_variable', 'force_https', 'use_htsts']):
        app = HttpsFixup(app, config)

    app = PermanentRepoUrl(app, config)

    # Optional and undocumented wrapper - gives more verbose request/response logging, but has a slight overhead
    if asbool(config.get('use_wsgi_wrapper')):
        app = RequestWrapper(app, config)

    return app


def make_app(global_conf, **app_conf):
    """
    Set up Kallithea with the settings found in the PasteDeploy configuration
    file used.

    :param global_conf: The global settings for Kallithea (those
        defined under the ``[DEFAULT]`` section).
    :return: The Kallithea application with all the relevant middleware
        loaded.

    This is the PasteDeploy factory for the Kallithea application.

    ``app_conf`` contains all the application-specific settings (those defined
    under ``[app:main]``.
    """
    assert app_conf.get('sqlalchemy.url')  # must be called with a Kallithea .ini file, which for example must have this config option
    assert global_conf.get('here') and global_conf.get('__file__')  # app config should be initialized the paste way ...

    return base_config.make_wsgi_app(global_conf, app_conf, wrap_app=wrap_app)
