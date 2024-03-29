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
kallithea.controllers.api.api
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

API controller for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Aug 20, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
import traceback
from datetime import datetime

from tg import request

from kallithea.controllers.api import JSONRPCController, JSONRPCError
from kallithea.lib.auth import (AuthUser, HasPermissionAny, HasPermissionAnyDecorator, HasRepoGroupPermissionLevel, HasRepoPermissionLevel,
                                HasUserGroupPermissionLevel)
from kallithea.lib.exceptions import DefaultUserException, UserGroupsAssignedException
from kallithea.lib.utils import repo2db_mapper
from kallithea.lib.vcs.backends.base import EmptyChangeset
from kallithea.lib.vcs.exceptions import EmptyRepositoryError
from kallithea.model import db, meta, userlog
from kallithea.model.changeset_status import ChangesetStatusModel
from kallithea.model.comment import ChangesetCommentsModel
from kallithea.model.gist import GistModel
from kallithea.model.pull_request import PullRequestModel
from kallithea.model.repo import RepoModel
from kallithea.model.repo_group import RepoGroupModel
from kallithea.model.scm import ScmModel, UserGroupList
from kallithea.model.user import UserModel
from kallithea.model.user_group import UserGroupModel


log = logging.getLogger(__name__)


def store_update(updates, attr, name):
    """
    Stores param in updates dict if it's not None (i.e. if user explicitly set
    a parameter). This allows easy updates of passed in params.
    """
    if attr is not None:
        updates[name] = attr


def get_user_or_error(userid):
    """
    Get user by id or name or return JsonRPCError if not found
    """
    user = UserModel().get_user(userid)
    if user is None:
        raise JSONRPCError("user `%s` does not exist" % (userid,))
    return user


def get_repo_or_error(repoid):
    """
    Get repo by id or name or return JsonRPCError if not found
    """
    repo = RepoModel().get_repo(repoid)
    if repo is None:
        raise JSONRPCError('repository `%s` does not exist' % (repoid,))
    return repo


def get_repo_group_or_error(repogroupid):
    """
    Get repo group by id or name or return JsonRPCError if not found
    """
    repo_group = db.RepoGroup.guess_instance(repogroupid)
    if repo_group is None:
        raise JSONRPCError(
            'repository group `%s` does not exist' % (repogroupid,))
    return repo_group


def get_user_group_or_error(usergroupid):
    """
    Get user group by id or name or return JsonRPCError if not found
    """
    user_group = UserGroupModel().get_group(usergroupid)
    if user_group is None:
        raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))
    return user_group


def get_perm_or_error(permid, prefix=None):
    """
    Get permission by id or name or return JsonRPCError if not found
    """
    perm = db.Permission.get_by_key(permid)
    if perm is None:
        raise JSONRPCError('permission `%s` does not exist' % (permid,))
    if prefix:
        if not perm.permission_name.startswith(prefix):
            raise JSONRPCError('permission `%s` is invalid, '
                               'should start with %s' % (permid, prefix))
    return perm


def get_gist_or_error(gistid):
    """
    Get gist by id or gist_access_id or return JsonRPCError if not found
    """
    gist = GistModel().get_gist(gistid)
    if gist is None:
        raise JSONRPCError('gist `%s` does not exist' % (gistid,))
    return gist


class ApiController(JSONRPCController):
    """
    API Controller

    The authenticated user can be found as request.authuser.

    Example function::

        def func(arg1, arg2,...):
            pass

    Each function should also **raise** JSONRPCError for any
    errors that happens.
    """

    @HasPermissionAnyDecorator('hg.admin')
    def test(self, args):
        return args

    @HasPermissionAnyDecorator('hg.admin')
    def pull(self, repoid, clone_uri=None):
        """
        Triggers a pull from remote location on given repo. Can be used to
        automatically keep remote repos up to date. This command can be executed
        only using api_key belonging to user with admin rights

        OUTPUT::

            id : <id_given_in_input>
            result : {
                "msg" : "Pulled from `<repository name>`",
                "repository" : "<repository name>"
            }
            error : null
        """
        repo = get_repo_or_error(repoid)

        try:
            ScmModel().pull_changes(repo.repo_name,
                                    request.authuser.username,
                                    request.ip_addr,
                                    clone_uri=clone_uri)
            return dict(
                msg='Pulled from `%s`' % repo.repo_name,
                repository=repo.repo_name
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'Unable to pull changes from `%s`' % repo.repo_name
            )

    @HasPermissionAnyDecorator('hg.admin')
    def rescan_repos(self, remove_obsolete=False):
        """
        Triggers rescan repositories action. If remove_obsolete is set
        than also delete repos that are in database but not in the filesystem.
        aka "clean zombies". This command can be executed only using api_key
        belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                'added': [<added repository name>,...]
                'removed': [<removed repository name>,...]
            }
            error : null
        """
        try:
            rm_obsolete = remove_obsolete
            added, removed = repo2db_mapper(ScmModel().repo_scan(),
                                            remove_obsolete=rm_obsolete)
            return {'added': added, 'removed': removed}
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'Error occurred during rescan repositories action'
            )

    def invalidate_cache(self, repoid):
        """
        Invalidate cache for repository.
        This command can be executed only using api_key belonging to user with admin
        rights or regular user that have write or admin or write access to repository.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                'msg': Cache for repository `<repository name>` was invalidated,
                'repository': <repository name>
            }
            error : null
        """
        repo = get_repo_or_error(repoid)
        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('write')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

        try:
            ScmModel().mark_for_invalidation(repo.repo_name)
            return dict(
                msg='Cache for repository `%s` was invalidated' % (repoid,),
                repository=repo.repo_name
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'Error occurred during cache invalidation action'
            )

    @HasPermissionAnyDecorator('hg.admin')
    def get_ip(self, userid=None):
        """
        Shows IP address as seen from Kallithea server, together with all
        defined IP addresses for given user. If userid is not passed data is
        returned for user who's calling this function.
        This command can be executed only using api_key belonging to user with
        admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                         "server_ip_addr" : "<ip_from_client>",
                         "user_ips" : [
                                        {
                                           "ip_addr" : "<ip_with_mask>",
                                           "ip_range" : ["<start_ip>", "<end_ip>"]
                                        },
                                        ...
                                      ]
            }
            error : null
        """
        if userid is None:
            userid = request.authuser.user_id
        user = get_user_or_error(userid)
        ips = db.UserIpMap.query().filter(db.UserIpMap.user == user).all()
        return dict(
            server_ip_addr=request.ip_addr,
            user_ips=ips
        )

    # alias for old
    show_ip = get_ip

    @HasPermissionAnyDecorator('hg.admin')
    def get_server_info(self):
        """
        return server info, including Kallithea version and installed packages

        OUTPUT::

            id : <id_given_in_input>
            result : {
                'modules' : [ [<module name>, <module version>], ...]
                'py_version' : <python version>,
                'platform' : <platform type>,
                'kallithea_version' : <kallithea version>,
                'git_version' : '<git version>',
                'git_path' : '<git path>'
            }
            error : null
        """
        return db.Setting.get_server_info()

    def get_user(self, userid=None):
        """
        Gets a user by username or user_id, Returns empty result if user is
        not found. If userid param is skipped it is set to id of user who is
        calling this method. This command can be executed only using api_key
        belonging to user with admin rights, or regular users that cannot
        specify different userid than theirs

        OUTPUT::

            id : <id_given_in_input>
            result : None if user does not exist or
                     {
                        "user_id" :     "<user_id>",
                        "username" :    "<username>",
                        "firstname" :   "<firstname>",
                        "lastname" :    "<lastname>",
                        "email" :       "<email>",
                        "emails" :      "[<list of all emails including additional ones>]",
                        "active" :      "<bool: user active>",
                        "admin" :       "<bool: user is admin>",
                        "permissions" : {
                            "global" : ["hg.create.repository",
                                        "repository.read",
                                        "hg.register.manual_activate"],
                            "repositories" : {"repo1" : "repository.none"},
                            "repositories_groups" : {"Group1" : "group.read"},
                            "user_groups" : { "usrgrp1" : "usergroup.admin" }
                         }
                     }
            error : null
        """
        if not HasPermissionAny('hg.admin')():
            # make sure normal user does not pass someone else userid,
            # he is not allowed to do that
            if userid is not None and userid != request.authuser.user_id:
                raise JSONRPCError(
                    'userid is not the same as your user'
                )

        if userid is None:
            userid = request.authuser.user_id

        user = get_user_or_error(userid)
        data = user.get_api_data()
        data['permissions'] = AuthUser(user_id=user.user_id).permissions
        return data

    @HasPermissionAnyDecorator('hg.admin')
    def get_users(self):
        """
        Lists all existing users. This command can be executed only using api_key
        belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : [<user_object>, ...]
            error : null
        """
        return [
            user.get_api_data()
            for user in db.User.query()
                .order_by(db.User.username)
                .filter_by(is_default_user=False)
        ]

    @HasPermissionAnyDecorator('hg.admin')
    def create_user(self, username, email, password='',
                    firstname='', lastname='',
                    active=True, admin=False,
                    extern_type=db.User.DEFAULT_AUTH_TYPE,
                    extern_name=''):
        """
        Creates new user. Returns new user object. This command can
        be executed only using api_key belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "created new user `<username>`",
                      "user" : <user_obj>
                     }
            error : null
        """
        if db.User.get_by_username(username):
            raise JSONRPCError("user `%s` already exist" % (username,))

        if db.User.get_by_email(email):
            raise JSONRPCError("email `%s` already exist" % (email,))

        try:
            user = UserModel().create_or_update(
                username=username,
                password=password,
                email=email,
                firstname=firstname,
                lastname=lastname,
                active=active,
                admin=admin,
                extern_type=extern_type,
                extern_name=extern_name
            )
            meta.Session().commit()
            return dict(
                msg='created new user `%s`' % username,
                user=user.get_api_data()
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to create user `%s`' % (username,))

    @HasPermissionAnyDecorator('hg.admin')
    def update_user(self, userid, username=None,
                    email=None, password=None,
                    firstname=None, lastname=None,
                    active=None, admin=None,
                    extern_type=None, extern_name=None):
        """
        updates given user if such user exists. This command can
        be executed only using api_key belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "updated user ID:<userid> <username>",
                      "user" : <user_object>
                     }
            error : null
        """
        user = get_user_or_error(userid)

        # only non optional arguments will be stored in updates
        updates = {}

        try:

            store_update(updates, username, 'username')
            store_update(updates, password, 'password')
            store_update(updates, email, 'email')
            store_update(updates, firstname, 'name')
            store_update(updates, lastname, 'lastname')
            store_update(updates, active, 'active')
            store_update(updates, admin, 'admin')
            store_update(updates, extern_name, 'extern_name')
            store_update(updates, extern_type, 'extern_type')

            user = UserModel().update_user(user, **updates)
            meta.Session().commit()
            return dict(
                msg='updated user ID:%s %s' % (user.user_id, user.username),
                user=user.get_api_data()
            )
        except DefaultUserException:
            log.error(traceback.format_exc())
            raise JSONRPCError('editing default user is forbidden')
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to update user `%s`' % (userid,))

    @HasPermissionAnyDecorator('hg.admin')
    def delete_user(self, userid):
        """
        deletes given user if such user exists. This command can
        be executed only using api_key belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "deleted user ID:<userid> <username>",
                      "user" : null
                     }
            error : null
        """
        user = get_user_or_error(userid)

        try:
            UserModel().delete(userid)
            meta.Session().commit()
            return dict(
                msg='deleted user ID:%s %s' % (user.user_id, user.username),
                user=None
            )
        except Exception:

            log.error(traceback.format_exc())
            raise JSONRPCError('failed to delete user ID:%s %s'
                               % (user.user_id, user.username))

    # permission check inside
    def get_user_group(self, usergroupid):
        """
        Gets an existing user group. This command can be executed only using api_key
        belonging to user with admin rights or user who has at least
        read access to user group.

        OUTPUT::

            id : <id_given_in_input>
            result : None if group not exist
                     {
                       "users_group_id" : "<id>",
                       "group_name" :     "<groupname>",
                       "group_description" : "<description>",
                       "active" :         "<bool>",
                       "owner" :          "<username>",
                       "members" :        [<user_obj>,...]
                     }
            error : null
        """
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasUserGroupPermissionLevel('read')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        data = user_group.get_api_data()
        return data

    # permission check inside
    def get_user_groups(self):
        """
        Lists all existing user groups. This command can be executed only using
        api_key belonging to user with admin rights or user who has at least
        read access to user group.

        OUTPUT::

            id : <id_given_in_input>
            result : [<user_group_obj>,...]
            error : null
        """
        return [
            user_group.get_api_data()
            for user_group in UserGroupList(db.UserGroup.query().all(), perm_level='read')
        ]

    @HasPermissionAnyDecorator('hg.admin', 'hg.usergroup.create.true')
    def create_user_group(self, group_name, description='',
                          owner=None, active=True):
        """
        Creates new user group. This command can be executed only using api_key
        belonging to user with admin rights or an user who has create user group
        permission

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "created new user group `<groupname>`",
                      "user_group" : <user_group_object>
                     }
            error : null
        """
        if UserGroupModel().get_by_name(group_name):
            raise JSONRPCError("user group `%s` already exist" % (group_name,))

        try:
            if owner is None:
                owner = request.authuser.user_id

            owner = get_user_or_error(owner)
            ug = UserGroupModel().create(name=group_name, description=description,
                                         owner=owner, active=active)
            meta.Session().commit()
            return dict(
                msg='created new user group `%s`' % group_name,
                user_group=ug.get_api_data()
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to create group `%s`' % (group_name,))

    # permission check inside
    def update_user_group(self, usergroupid, group_name=None,
                          description=None, owner=None,
                          active=None):
        """
        Updates given usergroup.  This command can be executed only using api_key
        belonging to user with admin rights or an admin of given user group

        OUTPUT::

          id : <id_given_in_input>
          result : {
            "msg" : 'updated user group ID:<user group id> <user group name>',
            "user_group" : <user_group_object>
          }
          error : null
        """
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasUserGroupPermissionLevel('admin')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        if owner is not None:
            owner = get_user_or_error(owner)

        updates = {}
        store_update(updates, group_name, 'users_group_name')
        store_update(updates, description, 'user_group_description')
        store_update(updates, owner, 'owner')
        store_update(updates, active, 'users_group_active')
        try:
            UserGroupModel().update(user_group, updates)
            meta.Session().commit()
            return dict(
                msg='updated user group ID:%s %s' % (user_group.users_group_id,
                                                     user_group.users_group_name),
                user_group=user_group.get_api_data()
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to update user group `%s`' % (usergroupid,))

    # permission check inside
    def delete_user_group(self, usergroupid):
        """
        Delete given user group by user group id or name.
        This command can be executed only using api_key
        belonging to user with admin rights or an admin of given user group

        OUTPUT::

          id : <id_given_in_input>
          result : {
            "msg" : "deleted user group ID:<user_group_id> <user_group_name>"
          }
          error : null
        """
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasUserGroupPermissionLevel('admin')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        try:
            UserGroupModel().delete(user_group)
            meta.Session().commit()
            return dict(
                msg='deleted user group ID:%s %s' %
                    (user_group.users_group_id, user_group.users_group_name),
                user_group=None
            )
        except UserGroupsAssignedException as e:
            log.error(traceback.format_exc())
            raise JSONRPCError(str(e))
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to delete user group ID:%s %s' %
                               (user_group.users_group_id,
                                user_group.users_group_name)
                               )

    # permission check inside
    def add_user_to_user_group(self, usergroupid, userid):
        """
        Adds a user to a user group. If user exists in that group success will be
        `false`. This command can be executed only using api_key
        belonging to user with admin rights or an admin of a given user group

        OUTPUT::

            id : <id_given_in_input>
            result : {
                "success" : True|False # depends on if member is in group
                "msg" : "added member `<username>` to a user group `<groupname>` |
                         User is already in that group"
            }
            error : null
        """
        user = get_user_or_error(userid)
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasUserGroupPermissionLevel('admin')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        try:
            ugm = UserGroupModel().add_user_to_group(user_group, user)
            success = True if ugm is not True else False
            msg = 'added member `%s` to user group `%s`' % (
                user.username, user_group.users_group_name
            )
            msg = msg if success else 'User is already in that group'
            meta.Session().commit()

            return dict(
                success=success,
                msg=msg
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to add member to user group `%s`' % (
                    user_group.users_group_name,
                )
            )

    # permission check inside
    def remove_user_from_user_group(self, usergroupid, userid):
        """
        Removes a user from a user group. If user is not in given group success will
        be `false`. This command can be executed only
        using api_key belonging to user with admin rights or an admin of given user group

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "success" : True|False,  # depends on if member is in group
                      "msg" : "removed member <username> from user group <groupname> |
                               User wasn't in group"
                     }
            error : null
        """
        user = get_user_or_error(userid)
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasUserGroupPermissionLevel('admin')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        try:
            success = UserGroupModel().remove_user_from_group(user_group, user)
            msg = 'removed member `%s` from user group `%s`' % (
                user.username, user_group.users_group_name
            )
            msg = msg if success else "User wasn't in group"
            meta.Session().commit()
            return dict(success=success, msg=msg)
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to remove member from user group `%s`' % (
                    user_group.users_group_name,
                )
            )

    # permission check inside
    def get_repo(self, repoid,
                 with_revision_names=False,
                 with_pullrequests=False):
        """
        Gets an existing repository by it's name or repository_id. Members will return
        either users_group or user associated to that repository. This command can be
        executed only using api_key belonging to user with admin
        rights or regular user that have at least read access to repository.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                        "repo_id" :          "<repo_id>",
                        "repo_name" :        "<reponame>",
                        "repo_type" :        "<repo_type>",
                        "clone_uri" :        "<clone_uri>",
                        "enable_downloads" : "<bool>",
                        "enable_statistics": "<bool>",
                        "private" :          "<bool>",
                        "created_on" :       "<date_time_created>",
                        "description" :      "<description>",
                        "landing_rev" :      "<landing_rev>",
                        "last_changeset" :   {
                                                 "author" :  "<full_author>",
                                                 "date" :    "<date_time_of_commit>",
                                                 "message" : "<commit_message>",
                                                 "raw_id" :  "<raw_id>",
                                                 "revision": "<numeric_revision>",
                                                 "short_id": "<short_id>"
                                             },
                        "owner" :            "<repo_owner>",
                        "fork_of" :          "<name_of_fork_parent>",
                        "members" :     [
                                            {
                                                "name" :    "<username>",
                                                "type" :    "user",
                                                "permission" : "repository.(read|write|admin)"
                                            },
                                            …
                                            {
                                                "name" :    "<usergroup name>",
                                                "type" :    "user_group",
                                                "permission" : "usergroup.(read|write|admin)"
                                            },
                                            …
                                        ],
                        "followers" :  [<user_obj>, ...],
                        <if with_revision_names == True>
                        "tags" : {
                                    "<tagname>" : "<raw_id>",
                                    ...
                                },
                        "branches" : {
                                    "<branchname>" : "<raw_id>",
                                    ...
                                },
                        "bookmarks" : {
                                    "<bookmarkname>" : "<raw_id>",
                                    ...
                                }
                     }
            error : null
        """
        repo = get_repo_or_error(repoid)

        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('read')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

        members = []
        for user in repo.repo_to_perm:
            perm = user.permission.permission_name
            user = user.user
            user_data = {
                'name': user.username,
                'type': "user",
                'permission': perm
            }
            members.append(user_data)

        for user_group in repo.users_group_to_perm:
            perm = user_group.permission.permission_name
            user_group = user_group.users_group
            user_group_data = {
                'name': user_group.users_group_name,
                'type': "user_group",
                'permission': perm
            }
            members.append(user_group_data)

        followers = [
            uf.user.get_api_data()
            for uf in repo.followers
        ]

        data = repo.get_api_data(with_revision_names=with_revision_names,
                                 with_pullrequests=with_pullrequests)
        data['members'] = members
        data['followers'] = followers
        return data

    # permission check inside
    def get_repos(self):
        """
        Lists all existing repositories. This command can be executed only using
        api_key belonging to user with admin rights or regular user that have
        admin, write or read access to repository.

        OUTPUT::

            id : <id_given_in_input>
            result : [
                      {
                        "repo_id" :          "<repo_id>",
                        "repo_name" :        "<reponame>",
                        "repo_type" :        "<repo_type>",
                        "clone_uri" :        "<clone_uri>",
                        "private" :          "<bool>",
                        "created_on" :       "<datetimecreated>",
                        "description" :      "<description>",
                        "landing_rev" :      "<landing_rev>",
                        "owner" :            "<repo_owner>",
                        "fork_of" :          "<name_of_fork_parent>",
                        "enable_downloads" : "<bool>",
                        "enable_statistics": "<bool>"
                      },
                      …
                     ]
            error : null
        """
        if not HasPermissionAny('hg.admin')():
            repos = request.authuser.get_all_user_repos()
        else:
            repos = db.Repository.query()

        return [
            repo.get_api_data()
            for repo in repos
        ]

    # permission check inside
    def get_repo_nodes(self, repoid, revision, root_path,
                       ret_type='all'):
        """
        returns a list of nodes and it's children in a flat list for a given path
        at given revision. It's possible to specify ret_type to show only `files` or
        `dirs`.  This command can be executed only using api_key belonging to
        user with admin rights or regular user that have at least read access to repository.

        OUTPUT::

            id : <id_given_in_input>
            result : [
                      {
                        "name" :        "<name>",
                        "type" :        "<type>"
                      },
                      …
                     ]
            error : null
        """
        repo = get_repo_or_error(repoid)

        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('read')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

        _map = {}
        try:
            _d, _f = ScmModel().get_nodes(repo, revision, root_path,
                                          flat=False)
            _map = {
                'all': _d + _f,
                'files': _f,
                'dirs': _d,
            }
            return _map[ret_type]
        except KeyError:
            raise JSONRPCError('ret_type must be one of %s'
                               % (','.join(sorted(_map))))
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to get repo: `%s` nodes' % repo.repo_name
            )

    # permission check inside
    def create_repo(self, repo_name, owner=None,
                    repo_type=None, description='',
                    private=False, clone_uri=None,
                    landing_rev='rev:tip',
                    enable_statistics=None,
                    enable_downloads=None,
                    copy_permissions=False):
        """
        Creates a repository. The repository name contains the full path, but the
        parent repository group must exist. For example "foo/bar/baz" require the groups
        "foo" and "bar" (with "foo" as parent), and create "baz" repository with
        "bar" as group. This command can be executed only using api_key
        belonging to user with admin rights or regular user that have create
        repository permission. Regular users cannot specify owner parameter

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Created new repository `<reponame>`",
                      "success" : true
                     }
            error : null
        """
        group_name = None
        repo_name_parts = repo_name.split('/')
        if len(repo_name_parts) > 1:
            group_name = '/'.join(repo_name_parts[:-1])
            repo_group = db.RepoGroup.get_by_group_name(group_name)
            if repo_group is None:
                raise JSONRPCError("repo group `%s` not found" % group_name)
            if not(HasPermissionAny('hg.admin')() or HasRepoGroupPermissionLevel('write')(group_name)):
                raise JSONRPCError("no permission to create repo in %s" % group_name)
        else:
            if not HasPermissionAny('hg.admin', 'hg.create.repository')():
                raise JSONRPCError("no permission to create top level repo")

        if not HasPermissionAny('hg.admin')():
            if owner is not None:
                # forbid setting owner for non-admins
                raise JSONRPCError(
                    'Only Kallithea admin can specify `owner` param'
                )
        if owner is None:
            owner = request.authuser.user_id

        owner = get_user_or_error(owner)

        if RepoModel().get_by_repo_name(repo_name):
            raise JSONRPCError("repo `%s` already exist" % repo_name)

        defs = db.Setting.get_default_repo_settings(strip_prefix=True)
        if private is None:
            private = defs.get('repo_private') or False
        if repo_type is None:
            repo_type = defs.get('repo_type')
        if enable_statistics is None:
            enable_statistics = defs.get('repo_enable_statistics')
        if enable_downloads is None:
            enable_downloads = defs.get('repo_enable_downloads')

        try:
            data = dict(
                repo_name=repo_name_parts[-1],
                repo_name_full=repo_name,
                repo_type=repo_type,
                repo_description=description,
                repo_private=private,
                clone_uri=clone_uri,
                repo_group=group_name,
                repo_landing_rev=landing_rev,
                repo_enable_statistics=enable_statistics,
                repo_enable_downloads=enable_downloads,
                repo_copy_permissions=copy_permissions,
            )

            RepoModel().create(form_data=data, cur_user=owner.username)
            # no commit, it's done in RepoModel, or async via celery
            return dict(
                msg="Created new repository `%s`" % (repo_name,),
                success=True,  # cannot return the repo data here since fork
                               # can be done async
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to create repository `%s`' % (repo_name,))

    # permission check inside
    def update_repo(self, repoid, name=None,
                    owner=None,
                    group=None,
                    description=None, private=None,
                    clone_uri=None, landing_rev=None,
                    enable_statistics=None,
                    enable_downloads=None):
        """
        Updates repo
        """
        repo = get_repo_or_error(repoid)
        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('admin')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

            if (name != repo.repo_name and repo.group_id is None and
                not HasPermissionAny('hg.create.repository')()
            ):
                raise JSONRPCError('no permission to create (or move) top level repositories')

            if owner is not None:
                # forbid setting owner for non-admins
                raise JSONRPCError(
                    'Only Kallithea admin can specify `owner` param'
                )

        updates = {}
        repo_group = group
        if repo_group is not None:
            repo_group = get_repo_group_or_error(repo_group)  # TODO: repos can thus currently not be moved to root
            if repo_group.group_id != repo.group_id:
                if not(HasPermissionAny('hg.admin')() or HasRepoGroupPermissionLevel('write')(repo_group.group_name)):
                    raise JSONRPCError("no permission to create (or move) repo in %s" % repo_group.group_name)
            repo_group = repo_group.group_id
        try:
            store_update(updates, name, 'repo_name')
            store_update(updates, repo_group, 'repo_group')
            store_update(updates, owner, 'owner')
            store_update(updates, description, 'repo_description')
            store_update(updates, private, 'repo_private')
            store_update(updates, clone_uri, 'clone_uri')
            store_update(updates, landing_rev, 'repo_landing_rev')
            store_update(updates, enable_statistics, 'repo_enable_statistics')
            store_update(updates, enable_downloads, 'repo_enable_downloads')

            RepoModel().update(repo, **updates)
            meta.Session().commit()
            return dict(
                msg='updated repo ID:%s %s' % (repo.repo_id, repo.repo_name),
                repository=repo.get_api_data()
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to update repo `%s`' % repoid)

    # permission check inside
    @HasPermissionAnyDecorator('hg.admin', 'hg.fork.repository')
    def fork_repo(self, repoid, fork_name,
                  owner=None,
                  description='', copy_permissions=False,
                  private=False, landing_rev='rev:tip'):
        """
        Creates a fork of given repo. In case of using celery this will
        immediately return success message, while fork is going to be created
        asynchronous. This command can be executed only using api_key belonging to
        user with admin rights or regular user that have fork permission, and at least
        read access to forking repository. Regular users cannot specify owner parameter.

        INPUT::

            id : <id_for_response>
            api_key : "<api_key>"
            method :  "fork_repo"
            args :    {
                        "repoid" :          "<reponame or repo_id>",
                        "fork_name" :       "<forkname>",
                        "owner" :           "<username or user_id = Optional(=apiuser)>",
                        "description" :     "<description>",
                        "copy_permissions": "<bool>",
                        "private" :         "<bool>",
                        "landing_rev" :     "<landing_rev>"
                      }

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Created fork of `<reponame>` as `<forkname>`",
                      "success" : true
                     }
            error : null
        """
        repo = get_repo_or_error(repoid)
        repo_name = repo.repo_name

        _repo = RepoModel().get_by_repo_name(fork_name)
        if _repo:
            type_ = 'fork' if _repo.fork else 'repo'
            raise JSONRPCError("%s `%s` already exist" % (type_, fork_name))

        group_name = None
        fork_name_parts = fork_name.split('/')
        if len(fork_name_parts) > 1:
            group_name = '/'.join(fork_name_parts[:-1])
            repo_group = db.RepoGroup.get_by_group_name(group_name)
            if repo_group is None:
                raise JSONRPCError("repo group `%s` not found" % group_name)
            if not(HasPermissionAny('hg.admin')() or HasRepoGroupPermissionLevel('write')(group_name)):
                raise JSONRPCError("no permission to create repo in %s" % group_name)
        else:
            if not HasPermissionAny('hg.admin', 'hg.create.repository')():
                raise JSONRPCError("no permission to create top level repo")

        if HasPermissionAny('hg.admin')():
            pass
        elif HasRepoPermissionLevel('read')(repo.repo_name):
            if owner is not None:
                # forbid setting owner for non-admins
                raise JSONRPCError(
                    'Only Kallithea admin can specify `owner` param'
                )
        else:
            raise JSONRPCError('repository `%s` does not exist' % (repoid,))

        if owner is None:
            owner = request.authuser.user_id

        owner = get_user_or_error(owner)

        try:
            form_data = dict(
                repo_name=fork_name_parts[-1],
                repo_name_full=fork_name,
                repo_group=group_name,
                repo_type=repo.repo_type,
                description=description,
                private=private,
                copy_permissions=copy_permissions,
                landing_rev=landing_rev,
                update_after_clone=False,
                fork_parent_id=repo.repo_id,
            )
            RepoModel().create_fork(form_data, cur_user=owner.username)
            # no commit, it's done in RepoModel, or async via celery
            return dict(
                msg='Created fork of `%s` as `%s`' % (repo.repo_name,
                                                      fork_name),
                success=True,  # cannot return the repo data here since fork
                               # can be done async
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to fork repository `%s` as `%s`' % (repo_name,
                                                            fork_name)
            )

    # permission check inside
    def delete_repo(self, repoid, forks=''):
        """
        Deletes a repository. This command can be executed only using api_key belonging
        to user with admin rights or regular user that have admin access to repository.
        When `forks` param is set it's possible to detach or delete forks of deleting
        repository

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Deleted repository `<reponame>`",
                      "success" : true
                     }
            error : null
        """
        repo = get_repo_or_error(repoid)

        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('admin')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

        try:
            handle_forks = forks
            _forks_msg = ''
            _forks = [f for f in repo.forks]
            if handle_forks == 'detach':
                _forks_msg = ' ' + 'Detached %s forks' % len(_forks)
            elif handle_forks == 'delete':
                _forks_msg = ' ' + 'Deleted %s forks' % len(_forks)
            elif _forks:
                raise JSONRPCError(
                    'Cannot delete `%s` it still contains attached forks' %
                    (repo.repo_name,)
                )

            RepoModel().delete(repo, forks=forks)
            meta.Session().commit()
            return dict(
                msg='Deleted repository `%s`%s' % (repo.repo_name, _forks_msg),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to delete repository `%s`' % (repo.repo_name,)
            )

    @HasPermissionAnyDecorator('hg.admin')
    def grant_user_permission(self, repoid, userid, perm):
        """
        Grant permission for user on given repository, or update existing one
        if found. This command can be executed only using api_key belonging to user
        with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Granted perm: `<perm>` for user: `<username>` in repo: `<reponame>`",
                      "success" : true
                     }
            error : null
        """
        repo = get_repo_or_error(repoid)
        user = get_user_or_error(userid)
        perm = get_perm_or_error(perm)

        try:

            RepoModel().grant_user_permission(repo=repo, user=user, perm=perm)

            meta.Session().commit()
            return dict(
                msg='Granted perm: `%s` for user: `%s` in repo: `%s`' % (
                    perm.permission_name, user.username, repo.repo_name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user: `%s` in repo: `%s`' % (
                    userid, repoid
                )
            )

    @HasPermissionAnyDecorator('hg.admin')
    def revoke_user_permission(self, repoid, userid):
        """
        Revoke permission for user on given repository. This command can be executed
        only using api_key belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Revoked perm for user: `<username>` in repo: `<reponame>`",
                      "success" : true
                     }
            error : null
        """
        repo = get_repo_or_error(repoid)
        user = get_user_or_error(userid)
        try:
            RepoModel().revoke_user_permission(repo=repo, user=user)
            meta.Session().commit()
            return dict(
                msg='Revoked perm for user: `%s` in repo: `%s`' % (
                    user.username, repo.repo_name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user: `%s` in repo: `%s`' % (
                    userid, repoid
                )
            )

    # permission check inside
    def grant_user_group_permission(self, repoid, usergroupid, perm):
        """
        Grant permission for user group on given repository, or update
        existing one if found. This command can be executed only using
        api_key belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                "msg" : "Granted perm: `<perm>` for group: `<usersgroupname>` in repo: `<reponame>`",
                "success" : true
            }
            error : null
        """
        repo = get_repo_or_error(repoid)
        perm = get_perm_or_error(perm)
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('admin')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

            if not HasUserGroupPermissionLevel('read')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        try:
            RepoModel().grant_user_group_permission(
                repo=repo, group_name=user_group, perm=perm)

            meta.Session().commit()
            return dict(
                msg='Granted perm: `%s` for user group: `%s` in '
                    'repo: `%s`' % (
                        perm.permission_name, user_group.users_group_name,
                        repo.repo_name
                    ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user group: `%s` in '
                'repo: `%s`' % (
                    usergroupid, repo.repo_name
                )
            )

    # permission check inside
    def revoke_user_group_permission(self, repoid, usergroupid):
        """
        Revoke permission for user group on given repository. This command can be
        executed only using api_key belonging to user with admin rights.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Revoked perm for group: `<usersgroupname>` in repo: `<reponame>`",
                      "success" : true
                     }
            error : null
        """
        repo = get_repo_or_error(repoid)
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasRepoPermissionLevel('admin')(repo.repo_name):
                raise JSONRPCError('repository `%s` does not exist' % (repoid,))

            if not HasUserGroupPermissionLevel('read')(user_group.users_group_name):
                raise JSONRPCError('user group `%s` does not exist' % (usergroupid,))

        try:
            RepoModel().revoke_user_group_permission(
                repo=repo, group_name=user_group)

            meta.Session().commit()
            return dict(
                msg='Revoked perm for user group: `%s` in repo: `%s`' % (
                    user_group.users_group_name, repo.repo_name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user group: `%s` in '
                'repo: `%s`' % (
                    user_group.users_group_name, repo.repo_name
                )
            )

    @HasPermissionAnyDecorator('hg.admin')
    def get_repo_group(self, repogroupid):
        """
        Returns given repo group together with permissions, and repositories
        inside the group
        """
        repo_group = get_repo_group_or_error(repogroupid)

        members = []
        for user in repo_group.repo_group_to_perm:
            perm = user.permission.permission_name
            user = user.user
            user_data = {
                'name': user.username,
                'type': "user",
                'permission': perm
            }
            members.append(user_data)

        for user_group in repo_group.users_group_to_perm:
            perm = user_group.permission.permission_name
            user_group = user_group.users_group
            user_group_data = {
                'name': user_group.users_group_name,
                'type': "user_group",
                'permission': perm
            }
            members.append(user_group_data)

        data = repo_group.get_api_data()
        data["members"] = members
        return data

    @HasPermissionAnyDecorator('hg.admin')
    def get_repo_groups(self):
        """
        Returns all repository groups
        """
        return [
            repo_group.get_api_data()
            for repo_group in db.RepoGroup.query()
        ]

    @HasPermissionAnyDecorator('hg.admin')
    def create_repo_group(self, group_name, description='',
                          owner=None,
                          parent=None,
                          copy_permissions=False):
        """
        Creates a repository group. This command can be executed only using
        api_key belonging to user with admin rights.

        OUTPUT::

          id : <id_given_in_input>
          result : {
              "msg" : "created new repo group `<repo_group_name>`",
              "repo_group" : <repogroup_object>
          }
          error : null
        """
        if db.RepoGroup.get_by_group_name(group_name):
            raise JSONRPCError("repo group `%s` already exist" % (group_name,))

        if owner is None:
            owner = request.authuser.user_id
        group_description = description
        parent_group = None
        if parent is not None:
            parent_group = get_repo_group_or_error(parent)

        try:
            repo_group = RepoGroupModel().create(
                group_name=group_name,
                group_description=group_description,
                owner=owner,
                parent=parent_group,
                copy_permissions=copy_permissions
            )
            meta.Session().commit()
            return dict(
                msg='created new repo group `%s`' % group_name,
                repo_group=repo_group.get_api_data()
            )
        except Exception:

            log.error(traceback.format_exc())
            raise JSONRPCError('failed to create repo group `%s`' % (group_name,))

    @HasPermissionAnyDecorator('hg.admin')
    def update_repo_group(self, repogroupid, group_name=None,
                          description=None,
                          owner=None,
                          parent=None):
        """
        TODO
        """
        repo_group = get_repo_group_or_error(repogroupid)
        parent_repo_group_id = None if parent is None else get_repo_group_or_error(parent).group_id

        updates = {}
        try:
            store_update(updates, group_name, 'group_name')
            store_update(updates, description, 'group_description')
            store_update(updates, owner, 'owner')
            store_update(updates, parent_repo_group_id, 'parent_group_id')
            repo_group = RepoGroupModel().update(repo_group, updates)
            meta.Session().commit()
            return dict(
                msg='updated repository group ID:%s %s' % (repo_group.group_id,
                                                           repo_group.group_name),
                repo_group=repo_group.get_api_data()
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to update repository group `%s`'
                               % (repogroupid,))

    @HasPermissionAnyDecorator('hg.admin')
    def delete_repo_group(self, repogroupid):
        """
        OUTPUT::

          id : <id_given_in_input>
          result : {
            'msg' : 'deleted repo group ID:<repogroupid> <repogroupname>
            'repo_group' : null
          }
          error : null
        """
        repo_group = get_repo_group_or_error(repogroupid)

        try:
            RepoGroupModel().delete(repo_group)
            meta.Session().commit()
            return dict(
                msg='deleted repo group ID:%s %s' %
                    (repo_group.group_id, repo_group.group_name),
                repo_group=None
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to delete repo group ID:%s %s' %
                               (repo_group.group_id, repo_group.group_name)
                               )

    # permission check inside
    def grant_user_permission_to_repo_group(self, repogroupid, userid,
                                            perm, apply_to_children='none'):
        """
        Grant permission for user on given repository group, or update existing
        one if found. This command can be executed only using api_key belonging
        to user with admin rights, or user who has admin right to given repository
        group.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Granted perm: `<perm>` (recursive:<apply_to_children>) for user: `<username>` in repo group: `<repo_group_name>`",
                      "success" : true
                     }
            error : null
        """
        repo_group = get_repo_group_or_error(repogroupid)

        if not HasPermissionAny('hg.admin')():
            if not HasRepoGroupPermissionLevel('admin')(repo_group.group_name):
                raise JSONRPCError('repository group `%s` does not exist' % (repogroupid,))

        user = get_user_or_error(userid)
        perm = get_perm_or_error(perm, prefix='group.')

        try:
            RepoGroupModel().add_permission(repo_group=repo_group,
                                            obj=user,
                                            obj_type="user",
                                            perm=perm,
                                            recursive=apply_to_children)
            meta.Session().commit()
            return dict(
                msg='Granted perm: `%s` (recursive:%s) for user: `%s` in repo group: `%s`' % (
                    perm.permission_name, apply_to_children, user.username, repo_group.name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user: `%s` in repo group: `%s`' % (
                    userid, repo_group.name))

    # permission check inside
    def revoke_user_permission_from_repo_group(self, repogroupid, userid,
                                               apply_to_children='none'):
        """
        Revoke permission for user on given repository group. This command can
        be executed only using api_key belonging to user with admin rights, or
        user who has admin right to given repository group.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Revoked perm (recursive:<apply_to_children>) for user: `<username>` in repo group: `<repo_group_name>`",
                      "success" : true
                     }
            error : null
        """
        repo_group = get_repo_group_or_error(repogroupid)

        if not HasPermissionAny('hg.admin')():
            if not HasRepoGroupPermissionLevel('admin')(repo_group.group_name):
                raise JSONRPCError('repository group `%s` does not exist' % (repogroupid,))

        user = get_user_or_error(userid)

        try:
            RepoGroupModel().delete_permission(repo_group=repo_group,
                                               obj=user,
                                               obj_type="user",
                                               recursive=apply_to_children)

            meta.Session().commit()
            return dict(
                msg='Revoked perm (recursive:%s) for user: `%s` in repo group: `%s`' % (
                    apply_to_children, user.username, repo_group.name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user: `%s` in repo group: `%s`' % (
                    userid, repo_group.name))

    # permission check inside
    def grant_user_group_permission_to_repo_group(
            self, repogroupid, usergroupid, perm,
            apply_to_children='none'):
        """
        Grant permission for user group on given repository group, or update
        existing one if found. This command can be executed only using
        api_key belonging to user with admin rights, or user who has admin
        right to given repository group.

        OUTPUT::

          id : <id_given_in_input>
          result : {
            "msg" : "Granted perm: `<perm>` (recursive:<apply_to_children>) for user group: `<usersgroupname>` in repo group: `<repo_group_name>`",
            "success" : true
          }
          error : null
        """
        repo_group = get_repo_group_or_error(repogroupid)
        perm = get_perm_or_error(perm, prefix='group.')
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasRepoGroupPermissionLevel('admin')(repo_group.group_name):
                raise JSONRPCError(
                    'repository group `%s` does not exist' % (repogroupid,))

            if not HasUserGroupPermissionLevel('read')(user_group.users_group_name):
                raise JSONRPCError(
                    'user group `%s` does not exist' % (usergroupid,))

        try:
            RepoGroupModel().add_permission(repo_group=repo_group,
                                            obj=user_group,
                                            obj_type="user_group",
                                            perm=perm,
                                            recursive=apply_to_children)
            meta.Session().commit()
            return dict(
                msg='Granted perm: `%s` (recursive:%s) for user group: `%s` in repo group: `%s`' % (
                    perm.permission_name, apply_to_children,
                    user_group.users_group_name, repo_group.name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user group: `%s` in '
                'repo group: `%s`' % (
                    usergroupid, repo_group.name
                )
            )

    # permission check inside
    def revoke_user_group_permission_from_repo_group(
            self, repogroupid, usergroupid,
            apply_to_children='none'):
        """
        Revoke permission for user group on given repository. This command can be
        executed only using api_key belonging to user with admin rights, or
        user who has admin right to given repository group.

        OUTPUT::

            id : <id_given_in_input>
            result : {
                      "msg" : "Revoked perm (recursive:<apply_to_children>) for user group: `<usersgroupname>` in repo group: `<repo_group_name>`",
                      "success" : true
                     }
            error : null
        """
        repo_group = get_repo_group_or_error(repogroupid)
        user_group = get_user_group_or_error(usergroupid)
        if not HasPermissionAny('hg.admin')():
            if not HasRepoGroupPermissionLevel('admin')(repo_group.group_name):
                raise JSONRPCError(
                    'repository group `%s` does not exist' % (repogroupid,))

            if not HasUserGroupPermissionLevel('read')(user_group.users_group_name):
                raise JSONRPCError(
                    'user group `%s` does not exist' % (usergroupid,))

        try:
            RepoGroupModel().delete_permission(repo_group=repo_group,
                                               obj=user_group,
                                               obj_type="user_group",
                                               recursive=apply_to_children)
            meta.Session().commit()
            return dict(
                msg='Revoked perm (recursive:%s) for user group: `%s` in repo group: `%s`' % (
                    apply_to_children, user_group.users_group_name, repo_group.name
                ),
                success=True
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError(
                'failed to edit permission for user group: `%s` in repo group: `%s`' % (
                    user_group.users_group_name, repo_group.name
                )
            )

    def get_gist(self, gistid):
        """
        Get given gist by id
        """
        gist = get_gist_or_error(gistid)
        if not HasPermissionAny('hg.admin')():
            if gist.owner_id != request.authuser.user_id:
                raise JSONRPCError('gist `%s` does not exist' % (gistid,))
        return gist.get_api_data()

    def get_gists(self, userid=None):
        """
        Get all gists for given user. If userid is empty returned gists
        are for user who called the api
        """
        if not HasPermissionAny('hg.admin')():
            # make sure normal user does not pass someone else userid,
            # he is not allowed to do that
            if userid is not None and userid != request.authuser.user_id:
                raise JSONRPCError(
                    'userid is not the same as your user'
                )

        if userid is None:
            user_id = request.authuser.user_id
        else:
            user_id = get_user_or_error(userid).user_id

        return [
            gist.get_api_data()
            for gist in db.Gist().query()
                .filter_by(is_expired=False)
                .filter(db.Gist.owner_id == user_id)
                .order_by(db.Gist.created_on.desc())
        ]

    def create_gist(self, files, owner=None,
                    gist_type=db.Gist.GIST_PUBLIC, lifetime=-1,
                    description=''):
        """
        Creates new Gist

        OUTPUT::

          id : <id_given_in_input>
          result : {
            "msg" : "created new gist",
            "gist" : <gist_object>
          }
          error : null
        """
        try:
            if owner is None:
                owner = request.authuser.user_id

            owner = get_user_or_error(owner)

            gist = GistModel().create(description=description,
                                      owner=owner,
                                      ip_addr=request.ip_addr,
                                      gist_mapping=files,
                                      gist_type=gist_type,
                                      lifetime=lifetime)
            meta.Session().commit()
            return dict(
                msg='created new gist',
                gist=gist.get_api_data()
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to create gist')

    # permission check inside
    def delete_gist(self, gistid):
        """
        Deletes existing gist

        OUTPUT::

          id : <id_given_in_input>
          result : {
            "msg" : "deleted gist ID: <gist_id>",
            "gist" : null
          }
          error : null
        """
        gist = get_gist_or_error(gistid)
        if not HasPermissionAny('hg.admin')():
            if gist.owner_id != request.authuser.user_id:
                raise JSONRPCError('gist `%s` does not exist' % (gistid,))

        try:
            GistModel().delete(gist)
            meta.Session().commit()
            return dict(
                msg='deleted gist ID:%s' % (gist.gist_access_id,),
                gist=None
            )
        except Exception:
            log.error(traceback.format_exc())
            raise JSONRPCError('failed to delete gist ID:%s'
                               % (gist.gist_access_id,))

    # permission check inside
    def get_changesets(self, repoid, start=None, end=None, start_date=None,
                       end_date=None, branch_name=None, reverse=False, with_file_list=False, max_revisions=None):
        """
        TODO
        """
        repo = get_repo_or_error(repoid)
        if not HasRepoPermissionLevel('read')(repo.repo_name):
            raise JSONRPCError('Access denied to repo %s' % repo.repo_name)

        format = "%Y-%m-%dT%H:%M:%S"
        try:
            return [e.__json__(with_file_list) for e in
                repo.scm_instance.get_changesets(start,
                                                 end,
                                                 datetime.strptime(start_date, format) if start_date else None,
                                                 datetime.strptime(end_date, format) if end_date else None,
                                                 branch_name,
                                                 reverse, max_revisions)]
        except EmptyRepositoryError as e:
            raise JSONRPCError('Repository is empty')

    # permission check inside
    def get_changeset(self, repoid, raw_id, with_reviews=False, with_comments=False, with_inline_comments=False):
        """
        TODO
        """
        repo = get_repo_or_error(repoid)
        if not HasRepoPermissionLevel('read')(repo.repo_name):
            raise JSONRPCError('Access denied to repo %s' % repo.repo_name)
        changeset = repo.get_changeset(raw_id)
        if isinstance(changeset, EmptyChangeset):
            raise JSONRPCError('Changeset %s does not exist' % raw_id)

        info = dict(changeset.as_dict())

        if with_reviews:
            reviews = ChangesetStatusModel().get_statuses(
                                repo.repo_name, changeset.raw_id)
            info["reviews"] = reviews

        if with_comments:
            comments = ChangesetCommentsModel().get_comments(
                                repo.repo_id, changeset.raw_id)
            info["comments"] = comments

        if with_inline_comments:
            inline_comments = ChangesetCommentsModel().get_inline_comments(
                                repo.repo_id, changeset.raw_id)
            info["inline_comments"] = inline_comments

        return info

    # permission check inside
    def get_pullrequest(self, pullrequest_id):
        """
        Get given pull request by id
        """
        pull_request = db.PullRequest.get(pullrequest_id)
        if pull_request is None:
            raise JSONRPCError('pull request `%s` does not exist' % (pullrequest_id,))
        if not HasRepoPermissionLevel('read')(pull_request.org_repo.repo_name):
            raise JSONRPCError('not allowed')
        return pull_request.get_api_data()

    # permission check inside
    def comment_pullrequest(self, pull_request_id, comment_msg='', status=None, close_pr=False):
        """
        Add comment, close and change status of pull request.
        """
        apiuser = get_user_or_error(request.authuser.user_id)
        pull_request = db.PullRequest.get(pull_request_id)
        if pull_request is None:
            raise JSONRPCError('pull request `%s` does not exist' % (pull_request_id,))
        if (not HasRepoPermissionLevel('read')(pull_request.org_repo.repo_name)):
            raise JSONRPCError('No permission to add comment. User needs at least reading permissions'
                               ' to the source repository.')
        owner = apiuser.user_id == pull_request.owner_id
        reviewer = apiuser.user_id in [reviewer.user_id for reviewer in pull_request.reviewers]
        if close_pr and not (apiuser.admin or owner):
            raise JSONRPCError('No permission to close pull request. User needs to be admin or owner.')
        if status and not (apiuser.admin or owner or reviewer):
            raise JSONRPCError('No permission to change pull request status. User needs to be admin, owner or reviewer.')
        if pull_request.is_closed():
            raise JSONRPCError('pull request is already closed')

        comment = ChangesetCommentsModel().create(
            text=comment_msg,
            repo=pull_request.org_repo.repo_id,
            author=apiuser.user_id,
            pull_request=pull_request.pull_request_id,
            f_path=None,
            line_no=None,
            status_change=db.ChangesetStatus.get_status_lbl(status),
            closing_pr=close_pr
        )
        userlog.action_logger(apiuser,
                      'user_commented_pull_request:%s' % pull_request_id,
                      pull_request.org_repo, request.ip_addr)
        if status:
            ChangesetStatusModel().set_status(
                pull_request.org_repo_id,
                status,
                apiuser.user_id,
                comment,
                pull_request=pull_request_id
            )
        if close_pr:
            PullRequestModel().close_pull_request(pull_request_id)
            userlog.action_logger(apiuser,
                          'user_closed_pull_request:%s' % pull_request_id,
                          pull_request.org_repo, request.ip_addr)
        meta.Session().commit()
        return True

    # permission check inside
    def edit_reviewers(self, pull_request_id, add=None, remove=None):
        """
        Add and/or remove one or more reviewers to a pull request, by username
        or user ID. Reviewers are specified either as a single-user string or
        as a JSON list of one or more strings.
        """
        if add is None and remove is None:
            raise JSONRPCError('''Invalid request. Neither 'add' nor 'remove' is specified.''')

        pull_request = db.PullRequest.get(pull_request_id)
        if pull_request is None:
            raise JSONRPCError('pull request `%s` does not exist' % (pull_request_id,))

        apiuser = get_user_or_error(request.authuser.user_id)
        is_owner = apiuser.user_id == pull_request.owner_id
        is_repo_admin = HasRepoPermissionLevel('admin')(pull_request.other_repo.repo_name)
        if not (apiuser.admin or is_repo_admin or is_owner):
            raise JSONRPCError('No permission to edit reviewers of this pull request. User needs to be admin or pull request owner.')
        if pull_request.is_closed():
            raise JSONRPCError('Cannot edit reviewers of a closed pull request.')

        if not isinstance(add, list):
            add = [add]
        if not isinstance(remove, list):
            remove = [remove]

        # look up actual user objects from given name or id. Bail out if unknown.
        add_objs = set(get_user_or_error(user) for user in add if user is not None)
        remove_objs = set(get_user_or_error(user) for user in remove if user is not None)

        new_reviewers = redundant_reviewers = set()
        if add_objs:
            new_reviewers, redundant_reviewers = PullRequestModel().add_reviewers(apiuser, pull_request, add_objs)
        if remove_objs:
            PullRequestModel().remove_reviewers(apiuser, pull_request, remove_objs)

        meta.Session().commit()

        return {
            'added': [x.username for x in new_reviewers],
            'already_present': [x.username for x in redundant_reviewers],
            # NOTE: no explicit check that removed reviewers were actually present.
            'removed': [x.username for x in remove_objs],
        }
