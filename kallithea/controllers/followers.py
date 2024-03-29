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
kallithea.controllers.followers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Followers controller for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 23, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging

from tg import request
from tg import tmpl_context as c

from kallithea.controllers import base
from kallithea.lib.auth import HasRepoPermissionLevelDecorator, LoginRequired
from kallithea.lib.page import Page
from kallithea.lib.utils2 import safe_int
from kallithea.model import db


log = logging.getLogger(__name__)


class FollowersController(base.BaseRepoController):

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    def followers(self, repo_name):
        p = safe_int(request.GET.get('page'), 1)
        repo_id = c.db_repo.repo_id
        d = db.UserFollowing.get_repo_followers(repo_id) \
            .order_by(db.UserFollowing.follows_from)
        c.followers_pager = Page(d, page=p, items_per_page=20)

        if request.environ.get('HTTP_X_PARTIAL_XHR'):
            return base.render('/followers/followers_data.html')

        return base.render('/followers/followers.html')
