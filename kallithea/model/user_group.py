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
kallithea.model.user_group
~~~~~~~~~~~~~~~~~~~~~~~~~~

user group model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Oct 1, 2011
:author: nvinot, marcink
"""


import logging
import traceback

from kallithea.lib.exceptions import RepoGroupAssignmentError, UserGroupsAssignedException
from kallithea.model import db, meta


log = logging.getLogger(__name__)


class UserGroupModel(object):

    def _create_default_perms(self, user_group):
        # create default permission
        default_perm = 'usergroup.read'
        def_user = db.User.get_default_user()
        for p in def_user.user_perms:
            if p.permission.permission_name.startswith('usergroup.'):
                default_perm = p.permission.permission_name
                break

        user_group_to_perm = db.UserUserGroupToPerm()
        user_group_to_perm.permission = db.Permission.get_by_key(default_perm)

        user_group_to_perm.user_group = user_group
        user_group_to_perm.user_id = def_user.user_id
        meta.Session().add(user_group_to_perm)
        return user_group_to_perm

    def _update_permissions(self, user_group, perms_new=None,
                            perms_updates=None):
        from kallithea.lib.auth import HasUserGroupPermissionLevel
        if not perms_new:
            perms_new = []
        if not perms_updates:
            perms_updates = []

        # update permissions
        for member, perm, member_type in perms_updates:
            if member_type == 'user':
                # this updates existing one
                self.grant_user_permission(
                    user_group=user_group, user=member, perm=perm
                )
            else:
                # check if we have permissions to alter this usergroup's access
                if HasUserGroupPermissionLevel('read')(member):
                    self.grant_user_group_permission(
                        target_user_group=user_group, user_group=member, perm=perm
                    )
        # set new permissions
        for member, perm, member_type in perms_new:
            if member_type == 'user':
                self.grant_user_permission(
                    user_group=user_group, user=member, perm=perm
                )
            else:
                # check if we have permissions to alter this usergroup's access
                if HasUserGroupPermissionLevel('read')(member):
                    self.grant_user_group_permission(
                        target_user_group=user_group, user_group=member, perm=perm
                    )

    def get(self, user_group_id):
        return db.UserGroup.get(user_group_id)

    def get_group(self, user_group):
        return db.UserGroup.guess_instance(user_group)

    def get_by_name(self, name, case_insensitive=False):
        return db.UserGroup.get_by_group_name(name, case_insensitive=case_insensitive)

    def create(self, name, description, owner, active=True, group_data=None):
        try:
            new_user_group = db.UserGroup()
            new_user_group.owner = db.User.guess_instance(owner)
            new_user_group.users_group_name = name
            new_user_group.user_group_description = description
            new_user_group.users_group_active = active
            if group_data:
                new_user_group.group_data = group_data
            meta.Session().add(new_user_group)
            self._create_default_perms(new_user_group)

            self.grant_user_permission(user_group=new_user_group,
                                       user=owner, perm='usergroup.admin')

            return new_user_group
        except Exception:
            log.error(traceback.format_exc())
            raise

    def update(self, user_group, form_data):

        try:
            user_group = db.UserGroup.guess_instance(user_group)

            for k, v in form_data.items():
                if k == 'users_group_members':
                    members_list = []
                    if v:
                        v = [v] if isinstance(v, str) else v
                        for u_id in set(v):
                            member = db.UserGroupMember(user_group.users_group_id, u_id)
                            members_list.append(member)
                            meta.Session().add(member)
                    user_group.members = members_list
                setattr(user_group, k, v)

            # Flush to make db assign users_group_member_id to newly
            # created UserGroupMembers.
            meta.Session().flush()
        except Exception:
            log.error(traceback.format_exc())
            raise

    def delete(self, user_group, force=False):
        """
        Deletes user group, unless force flag is used
        raises exception if there are members in that group, else deletes
        group and users

        :param user_group:
        :param force:
        """
        user_group = db.UserGroup.guess_instance(user_group)
        try:
            # check if this group is not assigned to repo
            assigned_groups = db.UserGroupRepoToPerm.query() \
                .filter(db.UserGroupRepoToPerm.users_group == user_group).all()
            assigned_groups = [x.repository.repo_name for x in assigned_groups]

            if assigned_groups and not force:
                raise UserGroupsAssignedException(
                    'User Group assigned to %s' % ", ".join(assigned_groups))
            meta.Session().delete(user_group)
        except Exception:
            log.error(traceback.format_exc())
            raise

    def add_user_to_group(self, user_group, user):
        """Return True if user already is in the group - else return the new UserGroupMember"""
        user_group = db.UserGroup.guess_instance(user_group)
        user = db.User.guess_instance(user)

        for m in user_group.members:
            u = m.user
            if u.user_id == user.user_id:
                # user already in the group, skip
                return True

        try:
            user_group_member = db.UserGroupMember()
            user_group_member.user = user
            user_group_member.users_group = user_group

            user_group.members.append(user_group_member)
            user.group_member.append(user_group_member)

            meta.Session().add(user_group_member)
            return user_group_member
        except Exception:
            log.error(traceback.format_exc())
            raise

    def remove_user_from_group(self, user_group, user):
        user_group = db.UserGroup.guess_instance(user_group)
        user = db.User.guess_instance(user)

        user_group_member = None
        for m in user_group.members:
            if m.user_id == user.user_id:
                # Found this user's membership row
                user_group_member = m
                break

        if user_group_member:
            try:
                meta.Session().delete(user_group_member)
                return True
            except Exception:
                log.error(traceback.format_exc())
                raise
        else:
            # User isn't in that group
            return False

    def has_perm(self, user_group, perm):
        user_group = db.UserGroup.guess_instance(user_group)
        perm = db.Permission.guess_instance(perm)

        return db.UserGroupToPerm.query() \
            .filter(db.UserGroupToPerm.users_group == user_group) \
            .filter(db.UserGroupToPerm.permission == perm).scalar() is not None

    def grant_perm(self, user_group, perm):
        user_group = db.UserGroup.guess_instance(user_group)
        perm = db.Permission.guess_instance(perm)

        # if this permission is already granted skip it
        _perm = db.UserGroupToPerm.query() \
            .filter(db.UserGroupToPerm.users_group == user_group) \
            .filter(db.UserGroupToPerm.permission == perm) \
            .scalar()
        if _perm:
            return

        new = db.UserGroupToPerm()
        new.users_group = user_group
        new.permission = perm
        meta.Session().add(new)
        return new

    def revoke_perm(self, user_group, perm):
        user_group = db.UserGroup.guess_instance(user_group)
        perm = db.Permission.guess_instance(perm)

        obj = db.UserGroupToPerm.query() \
            .filter(db.UserGroupToPerm.users_group == user_group) \
            .filter(db.UserGroupToPerm.permission == perm).scalar()
        if obj is not None:
            meta.Session().delete(obj)

    def grant_user_permission(self, user_group, user, perm):
        """
        Grant permission for user on given user group, or update
        existing one if found

        :param user_group: Instance of UserGroup, users_group_id,
            or users_group_name
        :param user: Instance of User, user_id or username
        :param perm: Instance of Permission, or permission_name
        """

        user_group = db.UserGroup.guess_instance(user_group)
        user = db.User.guess_instance(user)
        permission = db.Permission.guess_instance(perm)

        # check if we have that permission already
        obj = db.UserUserGroupToPerm.query() \
            .filter(db.UserUserGroupToPerm.user == user) \
            .filter(db.UserUserGroupToPerm.user_group == user_group) \
            .scalar()
        if obj is None:
            # create new !
            obj = db.UserUserGroupToPerm()
            meta.Session().add(obj)
        obj.user_group = user_group
        obj.user = user
        obj.permission = permission
        log.debug('Granted perm %s to %s on %s', perm, user, user_group)
        return obj

    def revoke_user_permission(self, user_group, user):
        """
        Revoke permission for user on given repository group

        :param user_group: Instance of RepoGroup, repositories_group_id,
            or repositories_group name
        :param user: Instance of User, user_id or username
        """

        user_group = db.UserGroup.guess_instance(user_group)
        user = db.User.guess_instance(user)

        obj = db.UserUserGroupToPerm.query() \
            .filter(db.UserUserGroupToPerm.user == user) \
            .filter(db.UserUserGroupToPerm.user_group == user_group) \
            .scalar()
        if obj is not None:
            meta.Session().delete(obj)
            log.debug('Revoked perm on %s on %s', user_group, user)

    def grant_user_group_permission(self, target_user_group, user_group, perm):
        """
        Grant user group permission for given target_user_group

        :param target_user_group:
        :param user_group:
        :param perm:
        """
        target_user_group = db.UserGroup.guess_instance(target_user_group)
        user_group = db.UserGroup.guess_instance(user_group)
        permission = db.Permission.guess_instance(perm)
        # forbid assigning same user group to itself
        if target_user_group == user_group:
            raise RepoGroupAssignmentError('target repo:%s cannot be '
                                           'assigned to itself' % target_user_group)

        # check if we have that permission already
        obj = db.UserGroupUserGroupToPerm.query() \
            .filter(db.UserGroupUserGroupToPerm.target_user_group == target_user_group) \
            .filter(db.UserGroupUserGroupToPerm.user_group == user_group) \
            .scalar()
        if obj is None:
            # create new !
            obj = db.UserGroupUserGroupToPerm()
            meta.Session().add(obj)
        obj.user_group = user_group
        obj.target_user_group = target_user_group
        obj.permission = permission
        log.debug('Granted perm %s to %s on %s', perm, target_user_group, user_group)
        return obj

    def revoke_user_group_permission(self, target_user_group, user_group):
        """
        Revoke user group permission for given target_user_group

        :param target_user_group:
        :param user_group:
        """
        target_user_group = db.UserGroup.guess_instance(target_user_group)
        user_group = db.UserGroup.guess_instance(user_group)

        obj = db.UserGroupUserGroupToPerm.query() \
            .filter(db.UserGroupUserGroupToPerm.target_user_group == target_user_group) \
            .filter(db.UserGroupUserGroupToPerm.user_group == user_group) \
            .scalar()
        if obj is not None:
            meta.Session().delete(obj)
            log.debug('Revoked perm on %s on %s', target_user_group, user_group)

    def enforce_groups(self, user, groups, extern_type=None):
        user = db.User.guess_instance(user)
        log.debug('Enforcing groups %s on user %s', user, groups)
        current_groups = user.group_member
        # find the external created groups
        externals = [x.users_group for x in current_groups
                     if 'extern_type' in x.users_group.group_data]

        # calculate from what groups user should be removed
        # externals that are not in groups
        for gr in externals:
            if gr.users_group_name not in groups:
                log.debug('Removing user %s from user group %s', user, gr)
                self.remove_user_from_group(gr, user)

        # now we calculate in which groups user should be == groups params
        owner = db.User.get_first_admin().username
        for gr in set(groups):
            existing_group = db.UserGroup.get_by_group_name(gr)
            if not existing_group:
                desc = 'Automatically created from plugin:%s' % extern_type
                # we use first admin account to set the owner of the group
                existing_group = UserGroupModel().create(gr, desc, owner,
                                        group_data={'extern_type': extern_type})

            # we can only add users to special groups created via plugins
            managed = 'extern_type' in existing_group.group_data
            if managed:
                log.debug('Adding user %s to user group %s', user, gr)
                UserGroupModel().add_user_to_group(existing_group, user)
            else:
                log.debug('Skipping addition to group %s since it is '
                          'not managed by auth plugins' % gr)
