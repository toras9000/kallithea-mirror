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
kallithea.model.repo_group
~~~~~~~~~~~~~~~~~~~~~~~~~~

repo group model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Jan 25, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import datetime
import logging
import os
import shutil
import traceback

import kallithea.lib.utils2
from kallithea.lib.utils2 import LazyProperty
from kallithea.model import db, meta, repo


log = logging.getLogger(__name__)


class RepoGroupModel(object):

    @LazyProperty
    def repos_path(self):
        """
        Gets the repositories root path from database
        """

        q = db.Ui.get_by_key('paths', '/')
        return q.ui_value

    def _create_default_perms(self, new_group):
        # create default permission
        default_perm = 'group.read'
        def_user = db.User.get_default_user()
        for p in def_user.user_perms:
            if p.permission.permission_name.startswith('group.'):
                default_perm = p.permission.permission_name
                break

        repo_group_to_perm = db.UserRepoGroupToPerm()
        repo_group_to_perm.permission = db.Permission.get_by_key(default_perm)

        repo_group_to_perm.group = new_group
        repo_group_to_perm.user_id = def_user.user_id
        meta.Session().add(repo_group_to_perm)
        return repo_group_to_perm

    def _create_group(self, group_name):
        """
        makes repository group on filesystem

        :param repo_name:
        :param parent_id:
        """

        create_path = os.path.join(self.repos_path, group_name)
        log.debug('creating new group in %s', create_path)

        if os.path.isdir(create_path):
            raise Exception('That directory already exists !')

        os.makedirs(create_path)
        log.debug('Created group in %s', create_path)

    def _rename_group(self, old, new):
        """
        Renames a group on filesystem

        :param group_name:
        """

        if old == new:
            log.debug('skipping group rename')
            return

        log.debug('renaming repository group from %s to %s', old, new)

        old_path = os.path.join(self.repos_path, old)
        new_path = os.path.join(self.repos_path, new)

        log.debug('renaming repos paths from %s to %s', old_path, new_path)

        if os.path.isdir(new_path):
            raise Exception('Was trying to rename to already '
                            'existing dir %s' % new_path)
        shutil.move(old_path, new_path)

    def _delete_group(self, group, force_delete=False):
        """
        Deletes a group from a filesystem

        :param group: instance of group from database
        :param force_delete: use shutil rmtree to remove all objects
        """
        paths = group.full_path.split(kallithea.URL_SEP)
        paths = os.sep.join(paths)

        rm_path = os.path.join(self.repos_path, paths)
        log.info("Removing group %s", rm_path)
        # delete only if that path really exists
        if os.path.isdir(rm_path):
            if force_delete:
                shutil.rmtree(rm_path)
            else:
                # archive that group
                _now = datetime.datetime.now()
                _ms = str(_now.microsecond).rjust(6, '0')
                _d = 'rm__%s_GROUP_%s' % (_now.strftime('%Y%m%d_%H%M%S_' + _ms),
                                          group.name)
                shutil.move(rm_path, os.path.join(self.repos_path, _d))

    def create(self, group_name, group_description, owner, parent=None,
               just_db=False, copy_permissions=False):
        try:
            if kallithea.lib.utils2.repo_name_slug(group_name) != group_name:
                raise Exception('invalid repo group name %s' % group_name)

            owner = db.User.guess_instance(owner)
            parent_group = db.RepoGroup.guess_instance(parent)
            new_repo_group = db.RepoGroup()
            new_repo_group.owner = owner
            new_repo_group.group_description = group_description or group_name
            new_repo_group.parent_group = parent_group
            new_repo_group.group_name = new_repo_group.get_new_name(group_name)

            meta.Session().add(new_repo_group)

            # create an ADMIN permission for owner except if we're super admin,
            # later owner should go into the owner field of groups
            if not owner.is_admin:
                self.grant_user_permission(repo_group=new_repo_group,
                                           user=owner, perm='group.admin')

            if parent_group and copy_permissions:
                # copy permissions from parent
                user_perms = db.UserRepoGroupToPerm.query() \
                    .filter(db.UserRepoGroupToPerm.group == parent_group).all()

                group_perms = db.UserGroupRepoGroupToPerm.query() \
                    .filter(db.UserGroupRepoGroupToPerm.group == parent_group).all()

                for perm in user_perms:
                    # don't copy over the permission for user who is creating
                    # this group, if he is not super admin he get's admin
                    # permission set above
                    if perm.user != owner or owner.is_admin:
                        db.UserRepoGroupToPerm.create(perm.user, new_repo_group, perm.permission)

                for perm in group_perms:
                    db.UserGroupRepoGroupToPerm.create(perm.users_group, new_repo_group, perm.permission)
            else:
                self._create_default_perms(new_repo_group)

            if not just_db:
                # we need to flush here, in order to check if database won't
                # throw any exceptions, create filesystem dirs at the very end
                meta.Session().flush()
                self._create_group(new_repo_group.group_name)

            return new_repo_group
        except Exception:
            log.error(traceback.format_exc())
            raise

    def _update_permissions(self, repo_group, perms_new=None,
                            perms_updates=None, recursive=None,
                            check_perms=True):
        from kallithea.lib.auth import HasUserGroupPermissionLevel

        if not perms_new:
            perms_new = []
        if not perms_updates:
            perms_updates = []

        def _set_perm_user(obj, user, perm):
            if isinstance(obj, db.RepoGroup):
                self.grant_user_permission(repo_group=obj, user=user, perm=perm)
            elif isinstance(obj, db.Repository):
                user = db.User.guess_instance(user)

                # private repos will not allow to change the default permissions
                # using recursive mode
                if obj.private and user.is_default_user:
                    return

                # we set group permission but we have to switch to repo
                # permission
                perm = perm.replace('group.', 'repository.')
                repo.RepoModel().grant_user_permission(
                    repo=obj, user=user, perm=perm
                )

        def _set_perm_group(obj, users_group, perm):
            if isinstance(obj, db.RepoGroup):
                self.grant_user_group_permission(repo_group=obj,
                                                  group_name=users_group,
                                                  perm=perm)
            elif isinstance(obj, db.Repository):
                # we set group permission but we have to switch to repo
                # permission
                perm = perm.replace('group.', 'repository.')
                repo.RepoModel().grant_user_group_permission(
                    repo=obj, group_name=users_group, perm=perm
                )

        # start updates
        updates = []
        log.debug('Now updating permissions for %s in recursive mode:%s',
                  repo_group, recursive)

        for obj in repo_group.recursive_groups_and_repos():
            # iterated obj is an instance of a repos group or repository in
            # that group, recursive option can be: none, repos, groups, all
            if recursive == 'all':
                pass
            elif recursive == 'repos':
                # skip groups, other than this one
                if isinstance(obj, db.RepoGroup) and not obj == repo_group:
                    continue
            elif recursive == 'groups':
                # skip repos
                if isinstance(obj, db.Repository):
                    continue
            else:  # recursive == 'none': # DEFAULT don't apply to iterated objects
                obj = repo_group
                # also we do a break at the end of this loop.

            # update permissions
            for member, perm, member_type in perms_updates:
                ## set for user
                if member_type == 'user':
                    # this updates also current one if found
                    _set_perm_user(obj, user=member, perm=perm)
                ## set for user group
                else:
                    # check if we have permissions to alter this usergroup's access
                    if not check_perms or HasUserGroupPermissionLevel('read')(member):
                        _set_perm_group(obj, users_group=member, perm=perm)
            # set new permissions
            for member, perm, member_type in perms_new:
                if member_type == 'user':
                    _set_perm_user(obj, user=member, perm=perm)
                else:
                    # check if we have permissions to alter this usergroup's access
                    if not check_perms or HasUserGroupPermissionLevel('read')(member):
                        _set_perm_group(obj, users_group=member, perm=perm)
            updates.append(obj)
            # if it's not recursive call for all,repos,groups
            # break the loop and don't proceed with other changes
            if recursive not in ['all', 'repos', 'groups']:
                break

        return updates

    def update(self, repo_group, repo_group_args):
        try:
            repo_group = db.RepoGroup.guess_instance(repo_group)
            old_path = repo_group.full_path  # aka .group_name

            if 'owner' in repo_group_args:
                repo_group.owner = db.User.get_by_username(repo_group_args['owner'])
            if 'group_description' in repo_group_args:
                repo_group.group_description = repo_group_args['group_description']
            if 'parent_group_id' in repo_group_args:
                assert repo_group_args['parent_group_id'] != '-1', repo_group_args  # RepoGroupForm should have converted to None
                new_parent_group = db.RepoGroup.get(repo_group_args['parent_group_id'])
                if new_parent_group is not repo_group.parent_group:
                    repo_group.parent_group = new_parent_group
                    repo_group.group_name = repo_group.get_new_name(repo_group.name)
                    log.debug('Moving repo group %s to %s', old_path, repo_group.group_name)
            if 'group_name' in repo_group_args:
                group_name = repo_group_args['group_name']
                if kallithea.lib.utils2.repo_name_slug(group_name) != group_name:
                    raise Exception('invalid repo group name %s' % group_name)
                if repo_group.name != group_name:
                    repo_group.group_name = repo_group.get_new_name(group_name)
                    log.debug('Renaming repo group %s to %s', old_path, repo_group.group_name)
            new_path = repo_group.full_path
            meta.Session().add(repo_group)

            # Iterate over all members of this repo group and update the full
            # path (repo_name and group_name) based on the (already updated)
            # full path of the parent.
            # This can potentially be a heavy operation.
            for obj in repo_group.recursive_groups_and_repos():
                if obj is repo_group:
                    continue  # already updated and logged
                if isinstance(obj, db.RepoGroup):
                    new_name = obj.get_new_name(obj.name)
                    log.debug('Fixing repo group %s to new name %s', obj.group_name, new_name)
                    obj.group_name = new_name
                elif isinstance(obj, db.Repository):
                    new_name = obj.get_new_name(obj.just_name)
                    log.debug('Fixing repo %s to new name %s', obj.repo_name, new_name)
                    obj.repo_name = new_name

            # Rename in file system
            self._rename_group(old_path, new_path)

            return repo_group
        except Exception:
            log.error(traceback.format_exc())
            raise

    def delete(self, repo_group, force_delete=False):
        repo_group = db.RepoGroup.guess_instance(repo_group)
        try:
            meta.Session().delete(repo_group)
            self._delete_group(repo_group, force_delete)
        except Exception:
            log.error('Error removing repo_group %s', repo_group)
            raise

    def add_permission(self, repo_group, obj, obj_type, perm, recursive):
        repo_group = db.RepoGroup.guess_instance(repo_group)
        perm = db.Permission.guess_instance(perm)

        for el in repo_group.recursive_groups_and_repos():
            # iterated obj is an instance of a repos group or repository in
            # that group, recursive option can be: none, repos, groups, all
            if recursive == 'all':
                pass
            elif recursive == 'repos':
                # skip groups, other than this one
                if isinstance(el, db.RepoGroup) and not el == repo_group:
                    continue
            elif recursive == 'groups':
                # skip repos
                if isinstance(el, db.Repository):
                    continue
            else:  # recursive == 'none': # DEFAULT don't apply to iterated objects
                el = repo_group
                # also we do a break at the end of this loop.

            if isinstance(el, db.RepoGroup):
                if obj_type == 'user':
                    RepoGroupModel().grant_user_permission(el, user=obj, perm=perm)
                elif obj_type == 'user_group':
                    RepoGroupModel().grant_user_group_permission(el, group_name=obj, perm=perm)
                else:
                    raise Exception('undefined object type %s' % obj_type)
            elif isinstance(el, db.Repository):
                # for repos we need to hotfix the name of permission
                _perm = perm.permission_name.replace('group.', 'repository.')
                if obj_type == 'user':
                    repo.RepoModel().grant_user_permission(el, user=obj, perm=_perm)
                elif obj_type == 'user_group':
                    repo.RepoModel().grant_user_group_permission(el, group_name=obj, perm=_perm)
                else:
                    raise Exception('undefined object type %s' % obj_type)
            else:
                raise Exception('el should be instance of Repository or '
                                'RepositoryGroup got %s instead' % type(el))

            # if it's not recursive call for all,repos,groups
            # break the loop and don't proceed with other changes
            if recursive not in ['all', 'repos', 'groups']:
                break

    def delete_permission(self, repo_group, obj, obj_type, recursive):
        """
        Revokes permission for repo_group for given obj(user or users_group),
        obj_type can be user or user group

        :param repo_group:
        :param obj: user or user group id
        :param obj_type: user or user group type
        :param recursive: recurse to all children of group
        """
        repo_group = db.RepoGroup.guess_instance(repo_group)

        for el in repo_group.recursive_groups_and_repos():
            # iterated obj is an instance of a repos group or repository in
            # that group, recursive option can be: none, repos, groups, all
            if recursive == 'all':
                pass
            elif recursive == 'repos':
                # skip groups, other than this one
                if isinstance(el, db.RepoGroup) and not el == repo_group:
                    continue
            elif recursive == 'groups':
                # skip repos
                if isinstance(el, db.Repository):
                    continue
            else:  # recursive == 'none': # DEFAULT don't apply to iterated objects
                el = repo_group
                # also we do a break at the end of this loop.

            if isinstance(el, db.RepoGroup):
                if obj_type == 'user':
                    RepoGroupModel().revoke_user_permission(el, user=obj)
                elif obj_type == 'user_group':
                    RepoGroupModel().revoke_user_group_permission(el, group_name=obj)
                else:
                    raise Exception('undefined object type %s' % obj_type)
            elif isinstance(el, db.Repository):
                if obj_type == 'user':
                    repo.RepoModel().revoke_user_permission(el, user=obj)
                elif obj_type == 'user_group':
                    repo.RepoModel().revoke_user_group_permission(el, group_name=obj)
                else:
                    raise Exception('undefined object type %s' % obj_type)
            else:
                raise Exception('el should be instance of Repository or '
                                'RepositoryGroup got %s instead' % type(el))

            # if it's not recursive call for all,repos,groups
            # break the loop and don't proceed with other changes
            if recursive not in ['all', 'repos', 'groups']:
                break

    def grant_user_permission(self, repo_group, user, perm):
        """
        Grant permission for user on given repository group, or update
        existing one if found

        :param repo_group: Instance of RepoGroup, repositories_group_id,
            or repositories_group name
        :param user: Instance of User, user_id or username
        :param perm: Instance of Permission, or permission_name
        """

        repo_group = db.RepoGroup.guess_instance(repo_group)
        user = db.User.guess_instance(user)
        permission = db.Permission.guess_instance(perm)

        # check if we have that permission already
        obj = db.UserRepoGroupToPerm.query() \
            .filter(db.UserRepoGroupToPerm.user == user) \
            .filter(db.UserRepoGroupToPerm.group == repo_group) \
            .scalar()
        if obj is None:
            # create new !
            obj = db.UserRepoGroupToPerm()
            meta.Session().add(obj)
        obj.group = repo_group
        obj.user = user
        obj.permission = permission
        log.debug('Granted perm %s to %s on %s', perm, user, repo_group)
        return obj

    def revoke_user_permission(self, repo_group, user):
        """
        Revoke permission for user on given repository group

        :param repo_group: Instance of RepoGroup, repositories_group_id,
            or repositories_group name
        :param user: Instance of User, user_id or username
        """

        repo_group = db.RepoGroup.guess_instance(repo_group)
        user = db.User.guess_instance(user)

        obj = db.UserRepoGroupToPerm.query() \
            .filter(db.UserRepoGroupToPerm.user == user) \
            .filter(db.UserRepoGroupToPerm.group == repo_group) \
            .scalar()
        if obj is not None:
            meta.Session().delete(obj)
            log.debug('Revoked perm on %s on %s', repo_group, user)

    def grant_user_group_permission(self, repo_group, group_name, perm):
        """
        Grant permission for user group on given repository group, or update
        existing one if found

        :param repo_group: Instance of RepoGroup, repositories_group_id,
            or repositories_group name
        :param group_name: Instance of UserGroup, users_group_id,
            or user group name
        :param perm: Instance of Permission, or permission_name
        """
        repo_group = db.RepoGroup.guess_instance(repo_group)
        group_name = db.UserGroup.guess_instance(group_name)
        permission = db.Permission.guess_instance(perm)

        # check if we have that permission already
        obj = db.UserGroupRepoGroupToPerm.query() \
            .filter(db.UserGroupRepoGroupToPerm.group == repo_group) \
            .filter(db.UserGroupRepoGroupToPerm.users_group == group_name) \
            .scalar()

        if obj is None:
            # create new
            obj = db.UserGroupRepoGroupToPerm()
            meta.Session().add(obj)

        obj.group = repo_group
        obj.users_group = group_name
        obj.permission = permission
        log.debug('Granted perm %s to %s on %s', perm, group_name, repo_group)
        return obj

    def revoke_user_group_permission(self, repo_group, group_name):
        """
        Revoke permission for user group on given repository group

        :param repo_group: Instance of RepoGroup, repositories_group_id,
            or repositories_group name
        :param group_name: Instance of UserGroup, users_group_id,
            or user group name
        """
        repo_group = db.RepoGroup.guess_instance(repo_group)
        group_name = db.UserGroup.guess_instance(group_name)

        obj = db.UserGroupRepoGroupToPerm.query() \
            .filter(db.UserGroupRepoGroupToPerm.group == repo_group) \
            .filter(db.UserGroupRepoGroupToPerm.users_group == group_name) \
            .scalar()
        if obj is not None:
            meta.Session().delete(obj)
            log.debug('Revoked perm to %s on %s', repo_group, group_name)
