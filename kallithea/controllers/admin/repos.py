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
kallithea.controllers.admin.repos
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Repositories controller for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 7, 2010
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
from webob.exc import HTTPForbidden, HTTPFound, HTTPInternalServerError, HTTPNotFound

import kallithea
from kallithea.controllers import base
from kallithea.lib import webutils
from kallithea.lib.auth import HasRepoPermissionLevelDecorator, LoginRequired, NotAnonymous
from kallithea.lib.exceptions import AttachedForksError
from kallithea.lib.utils2 import safe_int
from kallithea.lib.vcs import RepositoryError
from kallithea.lib.webutils import url
from kallithea.model import db, meta, userlog
from kallithea.model.forms import RepoFieldForm, RepoForm, RepoPermsForm
from kallithea.model.repo import RepoModel
from kallithea.model.scm import AvailableRepoGroupChoices, RepoList, ScmModel


log = logging.getLogger(__name__)


class ReposController(base.BaseRepoController):

    @LoginRequired(allow_default_user=True)
    def _before(self, *args, **kwargs):
        super(ReposController, self)._before(*args, **kwargs)

    def _load_repo(self):
        repo_obj = c.db_repo

        if repo_obj is None:
            raise HTTPNotFound()

        return repo_obj

    def __load_defaults(self, repo=None):
        extras = [] if repo is None else [repo.group]

        c.repo_groups = AvailableRepoGroupChoices('write', extras)

        c.landing_revs_choices, c.landing_revs = ScmModel().get_repo_landing_revs(repo)

    def __load_data(self):
        """
        Load defaults settings for edit, and update
        """
        c.repo_info = self._load_repo()
        self.__load_defaults(c.repo_info)

        defaults = RepoModel()._get_defaults(c.repo_name)
        defaults['clone_uri'] = c.repo_info.clone_uri_hidden # don't show password
        defaults['permanent_url'] = c.repo_info.clone_url(clone_uri_tmpl=c.clone_uri_tmpl, with_id=True)

        return defaults

    def index(self, format='html'):
        repos_list = RepoList(db.Repository.query(sorted=True).all(), perm_level='admin')
        # the repo list will be filtered to only show repos where the user has read permissions
        repos_data = RepoModel().get_repos_as_dict(repos_list, admin=True)
        # data used to render the grid
        c.data = repos_data

        return base.render('admin/repos/repos.html')

    @NotAnonymous()
    def create(self):
        self.__load_defaults()
        try:
            # CanWriteGroup validators checks permissions of this POST
            form_result = RepoForm(repo_groups=c.repo_groups,
                                   landing_revs=c.landing_revs_choices)() \
                            .to_python(dict(request.POST))
        except formencode.Invalid as errors:
            log.info(errors)
            return htmlfill.render(
                base.render('admin/repos/repo_add.html'),
                defaults=errors.value,
                errors=errors.error_dict or {},
                prefix_error=False,
                force_defaults=False,
                encoding="UTF-8")

        try:
            # create is done sometimes async on celery, db transaction
            # management is handled there.
            RepoModel().create(form_result, request.authuser.user_id)
        except Exception:
            log.error(traceback.format_exc())
            msg = (_('Error creating repository %s')
                   % form_result.get('repo_name'))
            webutils.flash(msg, category='error')
            raise HTTPFound(location=url('home'))

        raise HTTPFound(location=webutils.url('repo_creating_home',
                              repo_name=form_result['repo_name_full'],
                              ))

    @NotAnonymous()
    def create_repository(self):
        self.__load_defaults()
        if not c.repo_groups:
            raise HTTPForbidden
        parent_group = request.GET.get('parent_group')

        ## apply the defaults from defaults page
        defaults = db.Setting.get_default_repo_settings(strip_prefix=True)
        if parent_group:
            prg = db.RepoGroup.get(parent_group)
            if prg is None or not any(rgc[0] == prg.group_id
                                      for rgc in c.repo_groups):
                raise HTTPForbidden
        else:
            parent_group = '-1'
        defaults.update({'repo_group': parent_group})

        return htmlfill.render(
            base.render('admin/repos/repo_add.html'),
            defaults=defaults,
            errors={},
            prefix_error=False,
            encoding="UTF-8",
            force_defaults=False)

    @LoginRequired()
    def repo_creating(self, repo_name):
        c.repo = repo_name
        if not c.repo:
            raise HTTPNotFound()
        return base.render('admin/repos/repo_creating.html')

    @LoginRequired()
    @base.jsonify
    def repo_check(self, repo_name):
        c.repo = repo_name
        repo = db.Repository.get_by_repo_name(repo_name)
        if repo and repo.repo_state == db.Repository.STATE_CREATED:
            if repo.clone_uri:
                webutils.flash(_('Created repository %s from %s')
                        % (repo.repo_name, repo.clone_uri_hidden), category='success')
            else:
                repo_url = webutils.link_to(repo.repo_name,
                                     webutils.url('summary_home',
                                           repo_name=repo.repo_name))
                fork = repo.fork
                if fork is not None:
                    fork_name = fork.repo_name
                    webutils.flash(webutils.HTML(_('Forked repository %s as %s'))
                            % (fork_name, repo_url), category='success')
                else:
                    webutils.flash(webutils.HTML(_('Created repository %s')) % repo_url,
                            category='success')
            return {'result': True}
        return {'result': False}

    @HasRepoPermissionLevelDecorator('admin')
    def update(self, repo_name):
        c.repo_info = self._load_repo()
        self.__load_defaults(c.repo_info)
        c.active = 'settings'
        c.repo_fields = db.RepositoryField.query() \
            .filter(db.RepositoryField.repository == c.repo_info).all()

        repo_model = RepoModel()
        changed_name = repo_name
        repo = db.Repository.get_by_repo_name(repo_name)
        old_data = {
            'repo_name': repo_name,
            'repo_group': repo.group.get_dict() if repo.group else {},
            'repo_type': repo.repo_type,
        }
        _form = RepoForm(edit=True, old_data=old_data,
                         repo_groups=c.repo_groups,
                         landing_revs=c.landing_revs_choices)()

        try:
            form_result = _form.to_python(dict(request.POST))
            repo = repo_model.update(repo_name, **form_result)
            ScmModel().mark_for_invalidation(repo_name)
            webutils.flash(_('Repository %s updated successfully') % repo_name,
                    category='success')
            changed_name = repo.repo_name
            userlog.action_logger(request.authuser, 'admin_updated_repo',
                changed_name, request.ip_addr)
            meta.Session().commit()
        except formencode.Invalid as errors:
            log.info(errors)
            defaults = self.__load_data()
            defaults.update(errors.value)
            return htmlfill.render(
                base.render('admin/repos/repo_edit.html'),
                defaults=defaults,
                errors=errors.error_dict or {},
                prefix_error=False,
                encoding="UTF-8",
                force_defaults=False)

        except Exception:
            log.error(traceback.format_exc())
            webutils.flash(_('Error occurred during update of repository %s')
                    % repo_name, category='error')
        raise HTTPFound(location=url('edit_repo', repo_name=changed_name))

    @HasRepoPermissionLevelDecorator('admin')
    def delete(self, repo_name):
        repo_model = RepoModel()
        repo = repo_model.get_by_repo_name(repo_name)
        if not repo:
            raise HTTPNotFound()
        try:
            _forks = repo.forks.count()
            handle_forks = None
            if _forks and request.POST.get('forks'):
                do = request.POST['forks']
                if do == 'detach_forks':
                    handle_forks = 'detach'
                    webutils.flash(_('Detached %s forks') % _forks, category='success')
                elif do == 'delete_forks':
                    handle_forks = 'delete'
                    webutils.flash(_('Deleted %s forks') % _forks, category='success')
            repo_model.delete(repo, forks=handle_forks)
            userlog.action_logger(request.authuser, 'admin_deleted_repo',
                repo_name, request.ip_addr)
            ScmModel().mark_for_invalidation(repo_name)
            webutils.flash(_('Deleted repository %s') % repo_name, category='success')
            meta.Session().commit()
        except AttachedForksError:
            webutils.flash(_('Cannot delete repository %s which still has forks')
                        % repo_name, category='warning')

        except Exception:
            log.error(traceback.format_exc())
            webutils.flash(_('An error occurred during deletion of %s') % repo_name,
                    category='error')

        if repo.group:
            raise HTTPFound(location=url('repos_group_home', group_name=repo.group.group_name))
        raise HTTPFound(location=url('repos'))

    @HasRepoPermissionLevelDecorator('admin')
    def edit(self, repo_name):
        defaults = self.__load_data()
        c.repo_fields = db.RepositoryField.query() \
            .filter(db.RepositoryField.repository == c.repo_info).all()
        c.active = 'settings'
        return htmlfill.render(
            base.render('admin/repos/repo_edit.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasRepoPermissionLevelDecorator('admin')
    def edit_permissions(self, repo_name):
        c.repo_info = self._load_repo()
        c.active = 'permissions'
        defaults = RepoModel()._get_defaults(repo_name)

        return htmlfill.render(
            base.render('admin/repos/repo_edit.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasRepoPermissionLevelDecorator('admin')
    def edit_permissions_update(self, repo_name):
        form = RepoPermsForm()().to_python(request.POST)
        RepoModel()._update_permissions(repo_name, form['perms_new'],
                                        form['perms_updates'])
        # TODO: implement this
        #action_logger(request.authuser, 'admin_changed_repo_permissions',
        #              repo_name, request.ip_addr)
        meta.Session().commit()
        webutils.flash(_('Repository permissions updated'), category='success')
        raise HTTPFound(location=url('edit_repo_perms', repo_name=repo_name))

    @HasRepoPermissionLevelDecorator('admin')
    def edit_permissions_revoke(self, repo_name):
        try:
            obj_type = request.POST.get('obj_type')
            obj_id = None
            if obj_type == 'user':
                obj_id = safe_int(request.POST.get('user_id'))
            elif obj_type == 'user_group':
                obj_id = safe_int(request.POST.get('user_group_id'))
            else:
                assert False

            if obj_type == 'user':
                RepoModel().revoke_user_permission(repo=repo_name, user=obj_id)
            elif obj_type == 'user_group':
                RepoModel().revoke_user_group_permission(
                    repo=repo_name, group_name=obj_id
                )
            else:
                assert False
            # TODO: implement this
            #action_logger(request.authuser, 'admin_revoked_repo_permissions',
            #              repo_name, request.ip_addr)
            meta.Session().commit()
        except Exception:
            log.error(traceback.format_exc())
            webutils.flash(_('An error occurred during revoking of permission'),
                    category='error')
            raise HTTPInternalServerError()
        return []

    @HasRepoPermissionLevelDecorator('admin')
    def edit_fields(self, repo_name):
        c.repo_info = self._load_repo()
        c.repo_fields = db.RepositoryField.query() \
            .filter(db.RepositoryField.repository == c.repo_info).all()
        c.active = 'fields'
        if request.POST:

            raise HTTPFound(location=url('repo_edit_fields'))
        return base.render('admin/repos/repo_edit.html')

    @HasRepoPermissionLevelDecorator('admin')
    def create_repo_field(self, repo_name):
        try:
            form_result = RepoFieldForm()().to_python(dict(request.POST))
            new_field = db.RepositoryField()
            new_field.repository = db.Repository.get_by_repo_name(repo_name)
            new_field.field_key = form_result['new_field_key']
            new_field.field_type = form_result['new_field_type']  # python type
            new_field.field_value = form_result['new_field_value']  # set initial blank value
            new_field.field_desc = form_result['new_field_desc']
            new_field.field_label = form_result['new_field_label']
            meta.Session().add(new_field)
            meta.Session().commit()
        except formencode.Invalid as e:
            webutils.flash(_('Field validation error: %s') % e.msg, category='error')
        except Exception as e:
            log.error(traceback.format_exc())
            webutils.flash(_('An error occurred during creation of field: %r') % e, category='error')
        raise HTTPFound(location=url('edit_repo_fields', repo_name=repo_name))

    @HasRepoPermissionLevelDecorator('admin')
    def delete_repo_field(self, repo_name, field_id):
        field = db.RepositoryField.get_or_404(field_id)
        try:
            meta.Session().delete(field)
            meta.Session().commit()
        except Exception as e:
            log.error(traceback.format_exc())
            msg = _('An error occurred during removal of field')
            webutils.flash(msg, category='error')
        raise HTTPFound(location=url('edit_repo_fields', repo_name=repo_name))

    @HasRepoPermissionLevelDecorator('admin')
    def edit_advanced(self, repo_name):
        c.repo_info = self._load_repo()
        c.default_user_id = kallithea.DEFAULT_USER_ID
        c.in_public_journal = db.UserFollowing.query() \
            .filter(db.UserFollowing.user_id == c.default_user_id) \
            .filter(db.UserFollowing.follows_repository == c.repo_info).scalar()

        _repos = db.Repository.query(sorted=True).all()
        read_access_repos = RepoList(_repos, perm_level='read')
        c.repos_list = [(None, _('-- Not a fork --'))]
        c.repos_list += [(x.repo_id, x.repo_name)
                         for x in read_access_repos
                         if x.repo_id != c.repo_info.repo_id
                         and x.repo_type == c.repo_info.repo_type]

        defaults = {
            'id_fork_of': c.repo_info.fork_id if c.repo_info.fork_id else ''
        }

        c.active = 'advanced'
        if request.POST:
            raise HTTPFound(location=url('repo_edit_advanced'))
        return htmlfill.render(
            base.render('admin/repos/repo_edit.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasRepoPermissionLevelDecorator('admin')
    def edit_advanced_journal(self, repo_name):
        """
        Sets this repository to be visible in public journal,
        in other words asking default user to follow this repo

        :param repo_name:
        """

        try:
            repo_id = db.Repository.get_by_repo_name(repo_name).repo_id
            user_id = kallithea.DEFAULT_USER_ID
            self.scm_model.toggle_following_repo(repo_id, user_id)
            webutils.flash(_('Updated repository visibility in public journal'),
                    category='success')
            meta.Session().commit()
        except Exception:
            webutils.flash(_('An error occurred during setting this'
                      ' repository in public journal'),
                    category='error')
        raise HTTPFound(location=url('edit_repo_advanced', repo_name=repo_name))

    @HasRepoPermissionLevelDecorator('admin')
    def edit_advanced_fork(self, repo_name):
        """
        Mark given repository as a fork of another

        :param repo_name:
        """
        try:
            fork_id = request.POST.get('id_fork_of')
            repo = ScmModel().mark_as_fork(repo_name, fork_id,
                                           request.authuser.username)
            fork = repo.fork.repo_name if repo.fork else _('Nothing')
            meta.Session().commit()
            webutils.flash(_('Marked repository %s as fork of %s') % (repo_name, fork),
                    category='success')
        except RepositoryError as e:
            log.error(traceback.format_exc())
            webutils.flash(e, category='error')
        except Exception as e:
            log.error(traceback.format_exc())
            webutils.flash(_('An error occurred during this operation'),
                    category='error')

        raise HTTPFound(location=url('edit_repo_advanced', repo_name=repo_name))

    @HasRepoPermissionLevelDecorator('admin')
    def edit_remote(self, repo_name):
        c.repo_info = self._load_repo()
        c.active = 'remote'
        if request.POST:
            try:
                ScmModel().pull_changes(repo_name, request.authuser.username, request.ip_addr)
                webutils.flash(_('Pulled from remote location'), category='success')
            except Exception as e:
                log.error(traceback.format_exc())
                webutils.flash(_('An error occurred during pull from remote location'),
                        category='error')
            raise HTTPFound(location=url('edit_repo_remote', repo_name=c.repo_name))
        return base.render('admin/repos/repo_edit.html')

    @HasRepoPermissionLevelDecorator('admin')
    def edit_statistics(self, repo_name):
        c.repo_info = self._load_repo()
        repo = c.repo_info.scm_instance

        if c.repo_info.stats:
            # this is on what revision we ended up so we add +1 for count
            last_rev = c.repo_info.stats.stat_on_revision + 1
        else:
            last_rev = 0
        c.stats_revision = last_rev

        c.repo_last_rev = repo.count() if repo.revisions else 0

        if last_rev == 0 or c.repo_last_rev == 0:
            c.stats_percentage = 0
        else:
            c.stats_percentage = '%.2f' % ((float((last_rev)) / c.repo_last_rev) * 100)

        c.active = 'statistics'
        if request.POST:
            try:
                RepoModel().delete_stats(repo_name)
                meta.Session().commit()
            except Exception as e:
                log.error(traceback.format_exc())
                webutils.flash(_('An error occurred during deletion of repository stats'),
                        category='error')
            raise HTTPFound(location=url('edit_repo_statistics', repo_name=c.repo_name))

        return base.render('admin/repos/repo_edit.html')
