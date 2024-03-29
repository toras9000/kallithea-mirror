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
kallithea.controllers.forks
~~~~~~~~~~~~~~~~~~~~~~~~~~~

forks controller for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 23, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
import traceback

import formencode
from formencode import htmlfill
from tg import request
from tg import tmpl_context as c
from tg.i18n import ugettext as _
from webob.exc import HTTPFound, HTTPNotFound

import kallithea
from kallithea.controllers import base
from kallithea.lib import webutils
from kallithea.lib.auth import HasPermissionAnyDecorator, HasRepoPermissionLevel, HasRepoPermissionLevelDecorator, LoginRequired
from kallithea.lib.page import Page
from kallithea.lib.utils2 import safe_int
from kallithea.model import db
from kallithea.model.forms import RepoForkForm
from kallithea.model.repo import RepoModel
from kallithea.model.scm import AvailableRepoGroupChoices, ScmModel


log = logging.getLogger(__name__)


class ForksController(base.BaseRepoController):

    def __load_defaults(self):
        c.repo_groups = AvailableRepoGroupChoices('write')

        c.landing_revs_choices, c.landing_revs = ScmModel().get_repo_landing_revs()

        c.can_update = db.Ui.get_by_key('hooks', db.Ui.HOOK_UPDATE).ui_active

    def __load_data(self):
        """
        Load defaults settings for edit, and update
        """
        self.__load_defaults()

        c.repo_info = c.db_repo
        repo = c.db_repo.scm_instance

        if c.repo_info is None:
            raise HTTPNotFound()

        c.default_user_id = kallithea.DEFAULT_USER_ID
        c.in_public_journal = db.UserFollowing.query() \
            .filter(db.UserFollowing.user_id == c.default_user_id) \
            .filter(db.UserFollowing.follows_repository == c.repo_info).scalar()

        if c.repo_info.stats:
            last_rev = c.repo_info.stats.stat_on_revision + 1
        else:
            last_rev = 0
        c.stats_revision = last_rev

        c.repo_last_rev = repo.count() if repo.revisions else 0

        if last_rev == 0 or c.repo_last_rev == 0:
            c.stats_percentage = 0
        else:
            c.stats_percentage = '%.2f' % ((float((last_rev)) /
                                            c.repo_last_rev) * 100)

        defaults = RepoModel()._get_defaults(c.repo_name)
        # alter the description to indicate a fork
        defaults['description'] = ('fork of repository: %s \n%s'
                                   % (defaults['repo_name'],
                                      defaults['description']))
        # add suffix to fork
        defaults['repo_name'] = '%s-fork' % defaults['repo_name']

        return defaults

    @LoginRequired(allow_default_user=True)
    @HasRepoPermissionLevelDecorator('read')
    def forks(self, repo_name):
        p = safe_int(request.GET.get('page'), 1)
        repo_id = c.db_repo.repo_id
        d = []
        for r in db.Repository.get_repo_forks(repo_id):
            if not HasRepoPermissionLevel('read')(r.repo_name, 'get forks check'):
                continue
            d.append(r)
        c.forks_pager = Page(d, page=p, items_per_page=20)

        if request.environ.get('HTTP_X_PARTIAL_XHR'):
            return base.render('/forks/forks_data.html')

        return base.render('/forks/forks.html')

    @LoginRequired()
    @HasPermissionAnyDecorator('hg.admin', 'hg.fork.repository')
    @HasRepoPermissionLevelDecorator('read')
    def fork(self, repo_name):
        c.repo_info = db.Repository.get_by_repo_name(repo_name)
        if not c.repo_info:
            raise HTTPNotFound()

        defaults = self.__load_data()

        return htmlfill.render(
            base.render('forks/fork.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @LoginRequired()
    @HasPermissionAnyDecorator('hg.admin', 'hg.fork.repository')
    @HasRepoPermissionLevelDecorator('read')
    def fork_create(self, repo_name):
        self.__load_defaults()
        c.repo_info = db.Repository.get_by_repo_name(repo_name)
        _form = RepoForkForm(old_data={'repo_type': c.repo_info.repo_type},
                             repo_groups=c.repo_groups,
                             landing_revs=c.landing_revs_choices)()
        form_result = {}
        try:
            form_result = _form.to_python(dict(request.POST))

            # an approximation that is better than nothing
            if not db.Ui.get_by_key('hooks', db.Ui.HOOK_UPDATE).ui_active:
                form_result['update_after_clone'] = False

            # create fork is done sometimes async on celery, db transaction
            # management is handled there.
            RepoModel().create_fork(form_result, request.authuser.user_id)
        except formencode.Invalid as errors:
            return htmlfill.render(
                base.render('forks/fork.html'),
                defaults=errors.value,
                errors=errors.error_dict or {},
                prefix_error=False,
                encoding="UTF-8",
                force_defaults=False)
        except Exception:
            log.error(traceback.format_exc())
            webutils.flash(_('An error occurred during repository forking %s') %
                    repo_name, category='error')

        raise HTTPFound(location=webutils.url('repo_creating_home',
                              repo_name=form_result['repo_name_full'],
                              ))
