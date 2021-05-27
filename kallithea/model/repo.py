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
kallithea.model.repo
~~~~~~~~~~~~~~~~~~~~

Repository model for kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Jun 5, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.

"""

import logging
import os
import shutil
import traceback
from datetime import datetime

import kallithea.lib.utils2
from kallithea.lib import celerylib, hooks, webutils
from kallithea.lib.auth import HasRepoPermissionLevel, HasUserGroupPermissionLevel
from kallithea.lib.exceptions import AttachedForksError
from kallithea.lib.utils import is_valid_repo_uri, make_ui
from kallithea.lib.utils2 import LazyProperty, get_current_authuser, obfuscate_url_pw, remove_prefix
from kallithea.lib.vcs.backends import get_backend
from kallithea.model import db, meta, scm, userlog


log = logging.getLogger(__name__)


class RepoModel(object):

    def _create_default_perms(self, repository, private):
        # create default permission
        default = 'repository.read'
        def_user = db.User.get_default_user()
        for p in def_user.user_perms:
            if p.permission.permission_name.startswith('repository.'):
                default = p.permission.permission_name
                break

        default_perm = 'repository.none' if private else default

        repo_to_perm = db.UserRepoToPerm()
        repo_to_perm.permission = db.Permission.get_by_key(default_perm)

        repo_to_perm.repository = repository
        repo_to_perm.user_id = def_user.user_id
        meta.Session().add(repo_to_perm)

        return repo_to_perm

    @LazyProperty
    def repos_path(self):
        """
        Gets the repositories root path from database
        """

        q = db.Ui.query().filter(db.Ui.ui_key == '/').one()
        return q.ui_value

    def get(self, repo_id):
        repo = db.Repository.query() \
            .filter(db.Repository.repo_id == repo_id)
        return repo.scalar()

    def get_repo(self, repository):
        return db.Repository.guess_instance(repository)

    def get_by_repo_name(self, repo_name):
        repo = db.Repository.query() \
            .filter(db.Repository.repo_name == repo_name)
        return repo.scalar()

    @classmethod
    def _render_datatable(cls, tmpl, *args, **kwargs):
        from tg import app_globals, request
        from tg import tmpl_context as c
        from tg.i18n import ugettext as _

        _tmpl_lookup = app_globals.mako_lookup
        template = _tmpl_lookup.get_template('data_table/_dt_elements.html')

        tmpl = template.get_def(tmpl)
        return tmpl.render_unicode(
            *args,
            _=_,
            webutils=webutils,
            c=c,
            request=request,
            **kwargs)

    def get_repos_as_dict(self, repos_list, repo_groups_list=None,
                          admin=False,
                          short_name=False):
        """Return repository list for use by DataTable.
        repos_list: list of repositories - but will be filtered for read permission.
        repo_groups_list: added at top of list without permission check.
        admin: return data for action column.
        """
        _render = self._render_datatable
        from tg import request
        from tg import tmpl_context as c

        def repo_lnk(name, rtype, rstate, private, fork_of):
            return _render('repo_name', name, rtype, rstate, private, fork_of,
                           short_name=short_name)

        def following(repo_id, is_following):
            return _render('following', repo_id, is_following)

        def last_change(last_change):
            return _render("last_change", last_change)

        def rss_lnk(repo_name):
            return _render("rss", repo_name)

        def atom_lnk(repo_name):
            return _render("atom", repo_name)

        def last_rev(repo_name, cs_cache):
            return _render('revision', repo_name, cs_cache.get('revision'),
                           cs_cache.get('raw_id'), cs_cache.get('author'),
                           cs_cache.get('message'))

        def desc(desc):
            return webutils.urlify_text(desc, truncate=80, stylize=c.visual.stylify_metalabels)

        def state(repo_state):
            return _render("repo_state", repo_state)

        def repo_actions(repo_name):
            return _render('repo_actions', repo_name)

        def owner_actions(owner_id, username):
            return _render('user_name', owner_id, username)

        repos_data = []

        for gr in repo_groups_list or []:
            repos_data.append(dict(
                raw_name='\0' + webutils.html_escape(gr.name),  # sort before repositories
                just_name=webutils.html_escape(gr.name),
                name=_render('group_name_html', group_name=gr.group_name, name=gr.name),
                desc=desc(gr.group_description)))

        for repo in repos_list:
            if not HasRepoPermissionLevel('read')(repo.repo_name, 'get_repos_as_dict check'):
                continue
            cs_cache = repo.changeset_cache
            row = {
                "raw_name": webutils.html_escape(repo.repo_name),
                "just_name": webutils.html_escape(repo.just_name),
                "name": repo_lnk(repo.repo_name, repo.repo_type,
                                 repo.repo_state, repo.private, repo.fork),
                "following": following(
                    repo.repo_id,
                    scm.ScmModel().is_following_repo(repo.repo_name, request.authuser.user_id),
                ),
                "last_change_iso": repo.last_db_change.isoformat(),
                "last_change": last_change(repo.last_db_change),
                "last_changeset": last_rev(repo.repo_name, cs_cache),
                "last_rev_raw": cs_cache.get('revision'),
                "desc": desc(repo.description),
                "owner": repo.owner.username,
                "state": state(repo.repo_state),
                "rss": rss_lnk(repo.repo_name),
                "atom": atom_lnk(repo.repo_name),
            }
            if admin:
                row.update({
                    "action": repo_actions(repo.repo_name),
                    "owner": owner_actions(repo.owner_id, repo.owner.username)
                })
            repos_data.append(row)

        return {
            "sort": "name",
            "dir": "asc",
            "records": repos_data
        }

    def _get_defaults(self, repo_name):
        """
        Gets information about repository, and returns a dict for
        usage in forms

        :param repo_name:
        """

        repo_info = db.Repository.get_by_repo_name(repo_name)

        if repo_info is None:
            return None

        defaults = repo_info.get_dict()
        defaults['repo_name'] = repo_info.just_name
        defaults['repo_group'] = repo_info.group_id

        for strip, k in [(0, 'repo_type'), (1, 'repo_enable_downloads'),
                         (1, 'repo_description'),
                         (1, 'repo_landing_rev'), (0, 'clone_uri'),
                         (1, 'repo_private'), (1, 'repo_enable_statistics')]:
            attr = k
            if strip:
                attr = remove_prefix(k, 'repo_')

            val = defaults[attr]
            if k == 'repo_landing_rev':
                val = ':'.join(defaults[attr])
            defaults[k] = val
            if k == 'clone_uri':
                defaults['clone_uri_hidden'] = repo_info.clone_uri_hidden

        # fill owner
        if repo_info.owner:
            defaults.update({'owner': repo_info.owner.username})
        else:
            replacement_user = db.User.query().filter(db.User.admin ==
                                                   True).first().username
            defaults.update({'owner': replacement_user})

        # fill repository users
        for p in repo_info.repo_to_perm:
            defaults.update({'u_perm_%s' % p.user.username:
                                 p.permission.permission_name})

        # fill repository groups
        for p in repo_info.users_group_to_perm:
            defaults.update({'g_perm_%s' % p.users_group.users_group_name:
                                 p.permission.permission_name})

        return defaults

    def update(self, repo, **kwargs):
        try:
            cur_repo = db.Repository.guess_instance(repo)
            org_repo_name = cur_repo.repo_name
            if 'owner' in kwargs:
                cur_repo.owner = db.User.get_by_username(kwargs['owner'])

            if 'repo_group' in kwargs:
                assert kwargs['repo_group'] != '-1', kwargs # RepoForm should have converted to None
                cur_repo.group = db.RepoGroup.get(kwargs['repo_group'])
                cur_repo.repo_name = cur_repo.get_new_name(cur_repo.just_name)
            log.debug('Updating repo %s with params:%s', cur_repo, kwargs)
            for k in ['repo_enable_downloads',
                      'repo_description',
                      'repo_landing_rev',
                      'repo_private',
                      'repo_enable_statistics',
                      ]:
                if k in kwargs:
                    setattr(cur_repo, remove_prefix(k, 'repo_'), kwargs[k])
            clone_uri = kwargs.get('clone_uri')
            if clone_uri is not None and clone_uri != cur_repo.clone_uri_hidden:
                # clone_uri is modified - if given a value, check it is valid
                if clone_uri != '':
                    # will raise exception on error
                    is_valid_repo_uri(cur_repo.repo_type, clone_uri, make_ui())
                cur_repo.clone_uri = clone_uri

            if 'repo_name' in kwargs:
                repo_name = kwargs['repo_name']
                if kallithea.lib.utils2.repo_name_slug(repo_name) != repo_name:
                    raise Exception('invalid repo name %s' % repo_name)
                cur_repo.repo_name = cur_repo.get_new_name(repo_name)

            # if private flag is set, reset default permission to NONE
            if kwargs.get('repo_private'):
                EMPTY_PERM = 'repository.none'
                RepoModel().grant_user_permission(
                    repo=cur_repo, user='default', perm=EMPTY_PERM
                )
                # handle extra fields
            for field in [k for k in kwargs if k.startswith(db.RepositoryField.PREFIX)]:
                k = db.RepositoryField.un_prefix_key(field)
                ex_field = db.RepositoryField.get_by_key_name(key=k, repo=cur_repo)
                if ex_field:
                    ex_field.field_value = kwargs[field]

            if org_repo_name != cur_repo.repo_name:
                # rename repository
                self._rename_filesystem_repo(old=org_repo_name, new=cur_repo.repo_name)

            return cur_repo
        except Exception:
            log.error(traceback.format_exc())
            raise

    def _create_repo(self, repo_name, repo_type, description, owner,
                     private=False, clone_uri=None, repo_group=None,
                     landing_rev='rev:tip', fork_of=None,
                     copy_fork_permissions=False, enable_statistics=False,
                     enable_downloads=False,
                     copy_group_permissions=False, state=db.Repository.STATE_PENDING):
        """
        Create repository inside database with PENDING state. This should only be
        executed by create() repo, with exception of importing existing repos.

        """
        owner = db.User.guess_instance(owner)
        fork_of = db.Repository.guess_instance(fork_of)
        repo_group = db.RepoGroup.guess_instance(repo_group)
        try:
            # repo name is just a name of repository
            # while repo_name_full is a full qualified name that is combined
            # with name and path of group
            repo_name_full = repo_name
            repo_name = repo_name.split(kallithea.URL_SEP)[-1]
            if kallithea.lib.utils2.repo_name_slug(repo_name) != repo_name:
                raise Exception('invalid repo name %s' % repo_name)

            new_repo = db.Repository()
            new_repo.repo_state = state
            new_repo.enable_statistics = False
            new_repo.repo_name = repo_name_full
            new_repo.repo_type = repo_type
            new_repo.owner = owner
            new_repo.group = repo_group
            new_repo.description = description or repo_name
            new_repo.private = private
            if clone_uri:
                # will raise exception on error
                is_valid_repo_uri(repo_type, clone_uri, make_ui())
            new_repo.clone_uri = clone_uri
            new_repo.landing_rev = landing_rev

            new_repo.enable_statistics = enable_statistics
            new_repo.enable_downloads = enable_downloads

            if fork_of:
                parent_repo = fork_of
                new_repo.fork = parent_repo

            meta.Session().add(new_repo)

            if fork_of and copy_fork_permissions:
                repo = fork_of
                user_perms = db.UserRepoToPerm.query() \
                    .filter(db.UserRepoToPerm.repository == repo).all()
                group_perms = db.UserGroupRepoToPerm.query() \
                    .filter(db.UserGroupRepoToPerm.repository == repo).all()

                for perm in user_perms:
                    db.UserRepoToPerm.create(perm.user, new_repo, perm.permission)

                for perm in group_perms:
                    db.UserGroupRepoToPerm.create(perm.users_group, new_repo,
                                               perm.permission)

            elif repo_group and copy_group_permissions:

                user_perms = db.UserRepoGroupToPerm.query() \
                    .filter(db.UserRepoGroupToPerm.group == repo_group).all()

                group_perms = db.UserGroupRepoGroupToPerm.query() \
                    .filter(db.UserGroupRepoGroupToPerm.group == repo_group).all()

                for perm in user_perms:
                    perm_name = perm.permission.permission_name.replace('group.', 'repository.')
                    perm_obj = db.Permission.get_by_key(perm_name)
                    db.UserRepoToPerm.create(perm.user, new_repo, perm_obj)

                for perm in group_perms:
                    perm_name = perm.permission.permission_name.replace('group.', 'repository.')
                    perm_obj = db.Permission.get_by_key(perm_name)
                    db.UserGroupRepoToPerm.create(perm.users_group, new_repo, perm_obj)

            else:
                self._create_default_perms(new_repo, private)

            # now automatically start following this repository as owner
            scm.ScmModel().toggle_following_repo(new_repo.repo_id, owner.user_id)
            # we need to flush here, in order to check if database won't
            # throw any exceptions, create filesystem dirs at the very end
            meta.Session().flush()
            return new_repo
        except Exception:
            log.error(traceback.format_exc())
            raise

    def create(self, form_data, cur_user):
        """
        Create repository using celery tasks

        :param form_data:
        :param cur_user:
        """
        return create_repo(form_data, cur_user)

    def _update_permissions(self, repo, perms_new=None, perms_updates=None,
                            check_perms=True):
        if not perms_new:
            perms_new = []
        if not perms_updates:
            perms_updates = []

        # update permissions
        for member, perm, member_type in perms_updates:
            if member_type == 'user':
                # this updates existing one
                self.grant_user_permission(
                    repo=repo, user=member, perm=perm
                )
            else:
                # check if we have permissions to alter this usergroup's access
                if not check_perms or HasUserGroupPermissionLevel('read')(member):
                    self.grant_user_group_permission(
                        repo=repo, group_name=member, perm=perm
                    )
            # set new permissions
        for member, perm, member_type in perms_new:
            if member_type == 'user':
                self.grant_user_permission(
                    repo=repo, user=member, perm=perm
                )
            else:
                # check if we have permissions to alter this usergroup's access
                if not check_perms or HasUserGroupPermissionLevel('read')(member):
                    self.grant_user_group_permission(
                        repo=repo, group_name=member, perm=perm
                    )

    def create_fork(self, form_data, cur_user):
        """
        Simple wrapper into executing celery task for fork creation

        :param form_data:
        :param cur_user:
        """
        return create_repo_fork(form_data, cur_user)

    def delete(self, repo, forks=None, fs_remove=True, cur_user=None):
        """
        Delete given repository, forks parameter defines what do do with
        attached forks. Throws AttachedForksError if deleted repo has attached
        forks

        :param repo:
        :param forks: str 'delete' or 'detach'
        :param fs_remove: remove(archive) repo from filesystem
        """
        if not cur_user:
            cur_user = getattr(get_current_authuser(), 'username', None)
        repo = db.Repository.guess_instance(repo)
        if repo is not None:
            if forks == 'detach':
                for r in repo.forks:
                    r.fork = None
            elif forks == 'delete':
                for r in repo.forks:
                    self.delete(r, forks='delete')
            elif [f for f in repo.forks]:
                raise AttachedForksError()

            old_repo_dict = repo.get_dict()
            try:
                meta.Session().delete(repo)
                if fs_remove:
                    self._delete_filesystem_repo(repo)
                else:
                    log.debug('skipping removal from filesystem')
                hooks.log_delete_repository(old_repo_dict,
                                      deleted_by=cur_user)
            except Exception:
                log.error(traceback.format_exc())
                raise

    def grant_user_permission(self, repo, user, perm):
        """
        Grant permission for user on given repository, or update existing one
        if found

        :param repo: Instance of Repository, repository_id, or repository name
        :param user: Instance of User, user_id or username
        :param perm: Instance of Permission, or permission_name
        """
        user = db.User.guess_instance(user)
        repo = db.Repository.guess_instance(repo)
        permission = db.Permission.guess_instance(perm)

        # check if we have that permission already
        obj = db.UserRepoToPerm.query() \
            .filter(db.UserRepoToPerm.user == user) \
            .filter(db.UserRepoToPerm.repository == repo) \
            .scalar()
        if obj is None:
            # create new !
            obj = db.UserRepoToPerm()
            meta.Session().add(obj)
        obj.repository = repo
        obj.user = user
        obj.permission = permission
        log.debug('Granted perm %s to %s on %s', perm, user, repo)
        return obj

    def revoke_user_permission(self, repo, user):
        """
        Revoke permission for user on given repository

        :param repo: Instance of Repository, repository_id, or repository name
        :param user: Instance of User, user_id or username
        """

        user = db.User.guess_instance(user)
        repo = db.Repository.guess_instance(repo)

        obj = db.UserRepoToPerm.query() \
            .filter(db.UserRepoToPerm.repository == repo) \
            .filter(db.UserRepoToPerm.user == user) \
            .scalar()
        if obj is not None:
            meta.Session().delete(obj)
            log.debug('Revoked perm on %s on %s', repo, user)

    def grant_user_group_permission(self, repo, group_name, perm):
        """
        Grant permission for user group on given repository, or update
        existing one if found

        :param repo: Instance of Repository, repository_id, or repository name
        :param group_name: Instance of UserGroup, users_group_id,
            or user group name
        :param perm: Instance of Permission, or permission_name
        """
        repo = db.Repository.guess_instance(repo)
        group_name = db.UserGroup.guess_instance(group_name)
        permission = db.Permission.guess_instance(perm)

        # check if we have that permission already
        obj = db.UserGroupRepoToPerm.query() \
            .filter(db.UserGroupRepoToPerm.users_group == group_name) \
            .filter(db.UserGroupRepoToPerm.repository == repo) \
            .scalar()

        if obj is None:
            # create new
            obj = db.UserGroupRepoToPerm()
            meta.Session().add(obj)

        obj.repository = repo
        obj.users_group = group_name
        obj.permission = permission
        log.debug('Granted perm %s to %s on %s', perm, group_name, repo)
        return obj

    def revoke_user_group_permission(self, repo, group_name):
        """
        Revoke permission for user group on given repository

        :param repo: Instance of Repository, repository_id, or repository name
        :param group_name: Instance of UserGroup, users_group_id,
            or user group name
        """
        repo = db.Repository.guess_instance(repo)
        group_name = db.UserGroup.guess_instance(group_name)

        obj = db.UserGroupRepoToPerm.query() \
            .filter(db.UserGroupRepoToPerm.repository == repo) \
            .filter(db.UserGroupRepoToPerm.users_group == group_name) \
            .scalar()
        if obj is not None:
            meta.Session().delete(obj)
            log.debug('Revoked perm to %s on %s', repo, group_name)

    def delete_stats(self, repo_name):
        """
        removes stats for given repo

        :param repo_name:
        """
        repo = db.Repository.guess_instance(repo_name)
        try:
            obj = db.Statistics.query() \
                .filter(db.Statistics.repository == repo).scalar()
            if obj is not None:
                meta.Session().delete(obj)
        except Exception:
            log.error(traceback.format_exc())
            raise

    def _create_filesystem_repo(self, repo_name, repo_type, repo_group,
                                clone_uri=None, repo_store_location=None):
        """
        Makes repository on filesystem. Operation is group aware, meaning that it will create
        a repository within a group, and alter the paths accordingly to the group location.

        Note: clone_uri is low level and not validated - it might be a file system path used for validated cloning
        """
        from kallithea.lib.utils import is_valid_repo, is_valid_repo_group

        if '/' in repo_name:
            raise ValueError('repo_name must not contain groups got `%s`' % repo_name)

        if isinstance(repo_group, db.RepoGroup):
            new_parent_path = os.sep.join(repo_group.full_path_splitted)
        else:
            new_parent_path = repo_group or ''

        if repo_store_location:
            _paths = [repo_store_location]
        else:
            _paths = [self.repos_path, new_parent_path, repo_name]
        repo_path = os.path.join(*_paths)

        # check if this path is not a repository
        if is_valid_repo(repo_path, self.repos_path):
            raise Exception('This path %s is a valid repository' % repo_path)

        # check if this path is a group
        if is_valid_repo_group(repo_path, self.repos_path):
            raise Exception('This path %s is a valid group' % repo_path)

        log.info('creating repo %s in %s from url: `%s`',
            repo_name, repo_path,
            obfuscate_url_pw(clone_uri))

        backend = get_backend(repo_type)

        if repo_type == 'hg':
            baseui = make_ui()
            # patch and reset hooks section of UI config to not run any
            # hooks on creating remote repo
            for k, v in baseui.configitems('hooks'):
                baseui.setconfig('hooks', k, None)

            repo = backend(repo_path, create=True, src_url=clone_uri, baseui=baseui)
        elif repo_type == 'git':
            repo = backend(repo_path, create=True, src_url=clone_uri, bare=True)
            # add kallithea hook into this repo
            scm.ScmModel().install_git_hooks(repo)
        else:
            raise Exception('Not supported repo_type %s expected hg/git' % repo_type)

        log.debug('Created repo %s with %s backend',
                  repo_name, repo_type)
        return repo

    def _rename_filesystem_repo(self, old, new):
        """
        renames repository on filesystem

        :param old: old name
        :param new: new name
        """
        log.info('renaming repo from %s to %s', old, new)

        old_path = os.path.join(self.repos_path, old)
        new_path = os.path.join(self.repos_path, new)
        if os.path.isdir(new_path):
            raise Exception(
                'Was trying to rename to already existing dir %s' % new_path
            )
        shutil.move(old_path, new_path)

    def _delete_filesystem_repo(self, repo):
        """
        removes repo from filesystem, the removal is actually done by
        renaming dir to a 'rm__*' prefix which Kallithea will skip.
        It can be undeleted later by reverting the rename.

        :param repo: repo object
        """
        rm_path = os.path.join(self.repos_path, repo.repo_name)
        log.info("Removing %s", rm_path)

        _now = datetime.now()
        _ms = str(_now.microsecond).rjust(6, '0')
        _d = 'rm__%s__%s' % (_now.strftime('%Y%m%d_%H%M%S_' + _ms),
                             repo.just_name)
        if repo.group:
            args = repo.group.full_path_splitted + [_d]
            _d = os.path.join(*args)
        if os.path.exists(rm_path):
            shutil.move(rm_path, os.path.join(self.repos_path, _d))
        else:
            log.error("Can't find repo to delete in %r", rm_path)


@celerylib.task
def create_repo(form_data, cur_user):
    cur_user = db.User.guess_instance(cur_user)

    owner = cur_user
    repo_name = form_data['repo_name']
    repo_name_full = form_data['repo_name_full']
    repo_type = form_data['repo_type']
    description = form_data['repo_description']
    private = form_data['repo_private']
    clone_uri = form_data.get('clone_uri')
    repo_group = form_data['repo_group']
    landing_rev = form_data['repo_landing_rev']
    copy_fork_permissions = form_data.get('copy_permissions')
    copy_group_permissions = form_data.get('repo_copy_permissions')
    fork_of = form_data.get('fork_parent_id')
    state = form_data.get('repo_state', db.Repository.STATE_PENDING)

    # repo creation defaults, private and repo_type are filled in form
    defs = db.Setting.get_default_repo_settings(strip_prefix=True)
    enable_statistics = defs.get('repo_enable_statistics')
    enable_downloads = defs.get('repo_enable_downloads')

    try:
        db_repo = RepoModel()._create_repo(
            repo_name=repo_name_full,
            repo_type=repo_type,
            description=description,
            owner=owner,
            private=private,
            clone_uri=clone_uri,
            repo_group=repo_group,
            landing_rev=landing_rev,
            fork_of=fork_of,
            copy_fork_permissions=copy_fork_permissions,
            copy_group_permissions=copy_group_permissions,
            enable_statistics=enable_statistics,
            enable_downloads=enable_downloads,
            state=state
        )

        userlog.action_logger(cur_user, 'user_created_repo',
                      form_data['repo_name_full'], '')

        meta.Session().commit()
        # now create this repo on Filesystem
        RepoModel()._create_filesystem_repo(
            repo_name=repo_name,
            repo_type=repo_type,
            repo_group=db.RepoGroup.guess_instance(repo_group),
            clone_uri=clone_uri,
        )
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        hooks.log_create_repository(db_repo.get_dict(), created_by=owner.username)

        # update repo changeset caches initially
        db_repo.update_changeset_cache()

        # set new created state
        db_repo.set_state(db.Repository.STATE_CREATED)
        meta.Session().commit()
    except Exception as e:
        log.warning('Exception %s occurred when forking repository, '
                    'doing cleanup...' % e)
        # rollback things manually !
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        if db_repo:
            db.Repository.delete(db_repo.repo_id)
            meta.Session().commit()
            RepoModel()._delete_filesystem_repo(db_repo)
        raise


@celerylib.task
def create_repo_fork(form_data, cur_user):
    """
    Creates a fork of repository using interval VCS methods

    :param form_data:
    :param cur_user:
    """
    base_path = kallithea.CONFIG['base_path']
    cur_user = db.User.guess_instance(cur_user)

    repo_name = form_data['repo_name']  # fork in this case
    repo_name_full = form_data['repo_name_full']

    repo_type = form_data['repo_type']
    owner = cur_user
    private = form_data['private']
    clone_uri = form_data.get('clone_uri')
    repo_group = form_data['repo_group']
    landing_rev = form_data['landing_rev']
    copy_fork_permissions = form_data.get('copy_permissions')

    try:
        fork_of = db.Repository.guess_instance(form_data.get('fork_parent_id'))

        RepoModel()._create_repo(
            repo_name=repo_name_full,
            repo_type=repo_type,
            description=form_data['description'],
            owner=owner,
            private=private,
            clone_uri=clone_uri,
            repo_group=repo_group,
            landing_rev=landing_rev,
            fork_of=fork_of,
            copy_fork_permissions=copy_fork_permissions
        )
        userlog.action_logger(cur_user, 'user_forked_repo:%s' % repo_name_full,
                      fork_of.repo_name, '')
        meta.Session().commit()

        source_repo_path = os.path.join(base_path, fork_of.repo_name)

        # now create this repo on Filesystem
        RepoModel()._create_filesystem_repo(
            repo_name=repo_name,
            repo_type=repo_type,
            repo_group=db.RepoGroup.guess_instance(repo_group),
            clone_uri=source_repo_path,
        )
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        hooks.log_create_repository(db_repo.get_dict(), created_by=owner.username)

        # update repo changeset caches initially
        db_repo.update_changeset_cache()

        # set new created state
        db_repo.set_state(db.Repository.STATE_CREATED)
        meta.Session().commit()
    except Exception as e:
        log.warning('Exception %s occurred when forking repository, '
                    'doing cleanup...' % e)
        # rollback things manually !
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        if db_repo:
            db.Repository.delete(db_repo.repo_id)
            meta.Session().commit()
            RepoModel()._delete_filesystem_repo(db_repo)
        raise
