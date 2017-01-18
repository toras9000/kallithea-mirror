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
kallithea.model.base
~~~~~~~~~~~~~~~~~~~~

The application's model objects

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Nov 25, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import logging
from kallithea.model import meta
from kallithea.lib.utils2 import obfuscate_url_pw

log = logging.getLogger(__name__)


def init_model(engine):
    """
    Initializes db session, bind the engine with the metadata,
    Call this before using any of the tables or classes in the model,
    preferably once in application start

    :param engine: engine to bind to
    """
    engine_str = obfuscate_url_pw(str(engine.url))
    log.info("initializing db for %s", engine_str)
    meta.Base.metadata.bind = engine


class BaseModel(object):
    """
    Base Model for all Kallithea models, it adds sql alchemy session
    into instance of model

    :param sa: If passed it reuses this session instead of creating a new one
    """

    def __init__(self, sa=None):
        if sa is not None:
            self.sa = sa
        else:
            self.sa = meta.Session()

    def _get_repo(self, repository):
        """
        Helper method to get repository by ID, or repository name

        :param repository: RepoID, repository name or Repository Instance
        """
        from kallithea.model.db import Repository
        return Repository.guess_instance(repository)

    def _get_perm(self, permission):
        """
        Helper method to get permission by ID, or permission name

        :param permission: PermissionID, permission_name or Permission instance
        """
        from kallithea.model.db import Permission
        return Permission.guess_instance(permission)
