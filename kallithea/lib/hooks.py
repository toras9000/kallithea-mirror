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
kallithea.lib.hooks
~~~~~~~~~~~~~~~~~~~

Hooks run by Kallithea. Generally called 'log_*', but will also do important
invalidation of caches and run extension hooks.

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Aug 6, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import time

import kallithea
from kallithea.lib.exceptions import UserCreationError
from kallithea.lib.utils2 import get_hook_environment
from kallithea.model import userlog


def log_pull_action():
    """Logs user last pull action

    Does *not* use the action from the hook environment but is always 'pull'.
    """
    ex = get_hook_environment()

    action = 'pull'
    userlog.action_logger(ex.username, action, ex.repository, ex.ip, commit=True)
    # extension hook call
    callback = getattr(kallithea.EXTENSIONS, 'PULL_HOOK', None)
    if callable(callback):
        kw = {}
        kw.update(ex)
        callback(**kw)


def process_pushed_raw_ids(revs):
    """
    Register that changes have been added to the repo - log the action *and* invalidate caches.

    Called from Mercurial changegroup.kallithea_push_action calling hook push_action,
    or from the Git post-receive hook calling handle_git_post_receive ...
    or from scm _handle_push.
    """
    ex = get_hook_environment()

    action = '%s:%s' % (ex.action, ','.join(revs))
    userlog.action_logger(ex.username, action, ex.repository, ex.ip, commit=True)

    from kallithea.model.scm import ScmModel
    ScmModel().mark_for_invalidation(ex.repository)

    # extension hook call
    callback = getattr(kallithea.EXTENSIONS, 'PUSH_HOOK', None)
    if callable(callback):
        kw = {'pushed_revs': revs}
        kw.update(ex)
        callback(**kw)


def log_create_repository(repository_dict, created_by, **kwargs):
    """
    Post create repository Hook.

    :param repository: dict dump of repository object
    :param created_by: username who created repository

    available keys of repository_dict:

     'repo_type',
     'description',
     'private',
     'created_on',
     'enable_downloads',
     'repo_id',
     'owner_id',
     'enable_statistics',
     'clone_uri',
     'fork_id',
     'group_id',
     'repo_name'

    """
    callback = getattr(kallithea.EXTENSIONS, 'CREATE_REPO_HOOK', None)
    if callable(callback):
        kw = {}
        kw.update(repository_dict)
        kw.update({'created_by': created_by})
        kw.update(kwargs)
        callback(**kw)


def check_allowed_create_user(user_dict, created_by, **kwargs):
    # pre create hooks
    callback = getattr(kallithea.EXTENSIONS, 'PRE_CREATE_USER_HOOK', None)
    if callable(callback):
        allowed, reason = callback(created_by=created_by, **user_dict)
        if not allowed:
            raise UserCreationError(reason)


def log_create_user(user_dict, created_by, **kwargs):
    """
    Post create user Hook.

    :param user_dict: dict dump of user object

    available keys for user_dict:

     'username',
     'full_name_or_username',
     'full_contact',
     'user_id',
     'name',
     'firstname',
     'short_contact',
     'admin',
     'lastname',
     'ip_addresses',
     'ldap_dn',
     'email',
     'api_key',
     'last_login',
     'full_name',
     'active',
     'password',
     'emails',

    """
    callback = getattr(kallithea.EXTENSIONS, 'CREATE_USER_HOOK', None)
    if callable(callback):
        callback(created_by=created_by, **user_dict)


def log_create_pullrequest(pullrequest_dict, created_by, **kwargs):
    """
    Post create pull request hook.

    :param pullrequest_dict: dict dump of pull request object
    """
    callback = getattr(kallithea.EXTENSIONS, 'CREATE_PULLREQUEST_HOOK', None)
    if callable(callback):
        return callback(created_by=created_by, **pullrequest_dict)

    return 0

def log_delete_repository(repository_dict, deleted_by, **kwargs):
    """
    Post delete repository Hook.

    :param repository: dict dump of repository object
    :param deleted_by: username who deleted the repository

    available keys of repository_dict:

     'repo_type',
     'description',
     'private',
     'created_on',
     'enable_downloads',
     'repo_id',
     'owner_id',
     'enable_statistics',
     'clone_uri',
     'fork_id',
     'group_id',
     'repo_name'

    """
    callback = getattr(kallithea.EXTENSIONS, 'DELETE_REPO_HOOK', None)
    if callable(callback):
        kw = {}
        kw.update(repository_dict)
        kw.update({'deleted_by': deleted_by,
                   'deleted_on': time.time()})
        kw.update(kwargs)
        callback(**kw)


def log_delete_user(user_dict, deleted_by, **kwargs):
    """
    Post delete user Hook.

    :param user_dict: dict dump of user object

    available keys for user_dict:

     'username',
     'full_name_or_username',
     'full_contact',
     'user_id',
     'name',
     'firstname',
     'short_contact',
     'admin',
     'lastname',
     'ip_addresses',
     'ldap_dn',
     'email',
     'api_key',
     'last_login',
     'full_name',
     'active',
     'password',
     'emails',

    """
    callback = getattr(kallithea.EXTENSIONS, 'DELETE_USER_HOOK', None)
    if callable(callback):
        callback(deleted_by=deleted_by, **user_dict)
