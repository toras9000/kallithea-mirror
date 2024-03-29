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
kallithea.lib.auth
~~~~~~~~~~~~~~~~~~

authentication and permission libraries

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 4, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""
import itertools
import logging

import ipaddr
from decorator import decorator
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import ObjectDeletedError
from tg import request
from tg.i18n import ugettext as _
from webob.exc import HTTPForbidden, HTTPFound

import kallithea
from kallithea.lib import webutils
from kallithea.lib.utils import get_repo_group_slug, get_repo_slug, get_user_group_slug
from kallithea.lib.vcs.utils.lazy import LazyProperty
from kallithea.lib.webutils import url
from kallithea.model import db, meta
from kallithea.model.user import UserModel


log = logging.getLogger(__name__)


PERM_WEIGHTS = db.Permission.PERM_WEIGHTS

def bump_permission(permissions, key, new_perm):
    """Add a new permission for key to permissions.
    Assuming the permissions are comparable, set the new permission if it
    has higher weight, else drop it and keep the old permission.
    """
    cur_perm = permissions[key]
    new_perm_val = PERM_WEIGHTS[new_perm]
    cur_perm_val = PERM_WEIGHTS[cur_perm]
    if new_perm_val > cur_perm_val:
        permissions[key] = new_perm

class AuthUser(object):
    """
    Represents a Kallithea user, including various authentication and
    authorization information. Typically used to store the current user,
    but is also used as a generic user information data structure in
    parts of the code, e.g. user management.

    Constructed from a database `User` object, a user ID or cookie dict,
    it looks up the user (if needed) and copies all attributes to itself,
    adding various non-persistent data. If lookup fails but anonymous
    access to Kallithea is enabled, the default user is loaded instead.

    `AuthUser` does not by itself authenticate users. It's up to other parts of
    the code to check e.g. if a supplied password is correct, and if so, trust
    the AuthUser object as an authenticated user.

    However, `AuthUser` does refuse to load a user that is not `active`.

    Note that Kallithea distinguishes between the default user (an actual
    user in the database with username "default") and "no user" (no actual
    User object, AuthUser filled with blank values and username "None").

    If the default user is active, that will always be used instead of
    "no user". On the other hand, if the default user is disabled (and
    there is no login information), we instead get "no user"; this should
    only happen on the login page (as all other requests are redirected).

    `is_default_user` specifically checks if the AuthUser is the user named
    "default". Use `is_anonymous` to check for both "default" and "no user".
    """

    @classmethod
    def make(cls, dbuser=None, is_external_auth=False, ip_addr=None):
        """Create an AuthUser to be authenticated ... or return None if user for some reason can't be authenticated.
        Checks that a non-None dbuser is provided, is active, and that the IP address is ok.
        """
        assert ip_addr is not None
        if dbuser is None:
            log.info('No db user for authentication')
            return None
        if not dbuser.active:
            log.info('Db user %s not active', dbuser.username)
            return None
        allowed_ips = AuthUser.get_allowed_ips(dbuser.user_id)
        if not check_ip_access(source_ip=ip_addr, allowed_ips=allowed_ips):
            log.info('Access for %s from %s forbidden - not in %s', dbuser.username, ip_addr, allowed_ips)
            return None
        return cls(dbuser=dbuser, is_external_auth=is_external_auth)

    def __init__(self, user_id=None, dbuser=None, is_external_auth=False):
        self.is_external_auth = is_external_auth # container auth - don't show logout option

        # These attributes will be overridden below if the requested user is
        # found or anonymous access (using the default user) is enabled.
        self.user_id = None
        self.username = None
        self.api_key = None
        self.name = ''
        self.lastname = ''
        self.email = ''
        self.admin = False

        # Look up database user, if necessary.
        if user_id is not None:
            assert dbuser is None
            log.debug('Auth User lookup by USER ID %s', user_id)
            dbuser = UserModel().get(user_id)
            assert dbuser is not None
        else:
            assert dbuser is not None
            log.debug('Auth User lookup by database user %s', dbuser)

        log.debug('filling %s data', dbuser)
        self.is_anonymous = dbuser.is_default_user
        if dbuser.is_default_user and not dbuser.active:
            self.username = 'None'
            self.is_default_user = False
        else:
            # copy non-confidential database fields from a `db.User` to this `AuthUser`.
            for k, v in dbuser.get_dict().items():
                assert k not in ['api_keys', 'permissions']
                setattr(self, k, v)
            self.is_default_user = dbuser.is_default_user
        log.debug('Auth User is now %s', self)

    @LazyProperty
    def global_permissions(self):
        log.debug('Getting global permissions for %s', self)

        if self.is_admin:
            return set(['hg.admin'])

        global_permissions = set()

        # default global permissions from the default user
        default_global_perms = db.UserToPerm.query() \
            .filter(db.UserToPerm.user_id == kallithea.DEFAULT_USER_ID) \
            .options(joinedload(db.UserToPerm.permission))
        for perm in default_global_perms:
            global_permissions.add(perm.permission.permission_name)

        # user group global permissions
        user_perms_from_users_groups = meta.Session().query(db.UserGroupToPerm) \
            .options(joinedload(db.UserGroupToPerm.permission)) \
            .join((db.UserGroupMember, db.UserGroupToPerm.users_group_id ==
                   db.UserGroupMember.users_group_id)) \
            .filter(db.UserGroupMember.user_id == self.user_id) \
            .join((db.UserGroup, db.UserGroupMember.users_group_id ==
                   db.UserGroup.users_group_id)) \
            .filter(db.UserGroup.users_group_active == True) \
            .order_by(db.UserGroupToPerm.users_group_id) \
            .all()
        # need to group here by groups since user can be in more than
        # one group
        _grouped = [[x, list(y)] for x, y in
                    itertools.groupby(user_perms_from_users_groups,
                                      lambda x:x.users_group)]
        for gr, perms in _grouped:
            for perm in perms:
                global_permissions.add(perm.permission.permission_name)

        # user specific global permissions
        user_perms = meta.Session().query(db.UserToPerm) \
                .options(joinedload(db.UserToPerm.permission)) \
                .filter(db.UserToPerm.user_id == self.user_id).all()
        for perm in user_perms:
            global_permissions.add(perm.permission.permission_name)

        # for each kind of global permissions, only keep the one with heighest weight
        kind_max_perm = {}
        for perm in sorted(global_permissions, key=lambda n: PERM_WEIGHTS.get(n, -1)):
            kind = perm.rsplit('.', 1)[0]
            kind_max_perm[kind] = perm
        return set(kind_max_perm.values())

    @LazyProperty
    def repository_permissions(self):
        log.debug('Getting repository permissions for %s', self)
        repository_permissions = {}
        default_repo_perms = db.Permission.get_default_perms(kallithea.DEFAULT_USER_ID)

        if self.is_admin:
            for perm in default_repo_perms:
                r_k = perm.repository.repo_name
                p = 'repository.admin'
                repository_permissions[r_k] = p

        else:
            # defaults for repositories from default user
            for perm in default_repo_perms:
                r_k = perm.repository.repo_name
                if perm.repository.owner_id == self.user_id:
                    p = 'repository.admin'
                elif perm.repository.private:
                    p = 'repository.none'
                else:
                    p = perm.permission.permission_name
                repository_permissions[r_k] = p

            # user group repository permissions
            user_repo_perms_from_users_groups = \
             meta.Session().query(db.UserGroupRepoToPerm) \
                .join((db.UserGroup, db.UserGroupRepoToPerm.users_group_id ==
                       db.UserGroup.users_group_id)) \
                .filter(db.UserGroup.users_group_active == True) \
                .join((db.UserGroupMember, db.UserGroupRepoToPerm.users_group_id ==
                       db.UserGroupMember.users_group_id)) \
                .filter(db.UserGroupMember.user_id == self.user_id) \
                .options(joinedload(db.UserGroupRepoToPerm.repository)) \
                .options(joinedload(db.UserGroupRepoToPerm.permission)) \
                .all()
            for perm in user_repo_perms_from_users_groups:
                bump_permission(repository_permissions,
                    perm.repository.repo_name,
                    perm.permission.permission_name)

            # user permissions for repositories
            user_repo_perms = db.Permission.get_default_perms(self.user_id)
            for perm in user_repo_perms:
                bump_permission(repository_permissions,
                    perm.repository.repo_name,
                    perm.permission.permission_name)

        return repository_permissions

    @LazyProperty
    def repository_group_permissions(self):
        log.debug('Getting repository group permissions for %s', self)
        repository_group_permissions = {}
        default_repo_groups_perms = db.Permission.get_default_group_perms(kallithea.DEFAULT_USER_ID)

        if self.is_admin:
            for perm in default_repo_groups_perms:
                rg_k = perm.group.group_name
                p = 'group.admin'
                repository_group_permissions[rg_k] = p

        else:
            # defaults for repository groups taken from default user permission
            # on given group
            for perm in default_repo_groups_perms:
                rg_k = perm.group.group_name
                p = perm.permission.permission_name
                repository_group_permissions[rg_k] = p

            # user group for repo groups permissions
            user_repo_group_perms_from_users_groups = \
                meta.Session().query(db.UserGroupRepoGroupToPerm) \
                .join((db.UserGroup, db.UserGroupRepoGroupToPerm.users_group_id ==
                       db.UserGroup.users_group_id)) \
                .filter(db.UserGroup.users_group_active == True) \
                .join((db.UserGroupMember, db.UserGroupRepoGroupToPerm.users_group_id
                       == db.UserGroupMember.users_group_id)) \
                .filter(db.UserGroupMember.user_id == self.user_id) \
                .options(joinedload(db.UserGroupRepoGroupToPerm.permission)) \
                .all()
            for perm in user_repo_group_perms_from_users_groups:
                bump_permission(repository_group_permissions,
                    perm.group.group_name,
                    perm.permission.permission_name)

            # user explicit permissions for repository groups
            user_repo_groups_perms = db.Permission.get_default_group_perms(self.user_id)
            for perm in user_repo_groups_perms:
                bump_permission(repository_group_permissions,
                    perm.group.group_name,
                    perm.permission.permission_name)

        return repository_group_permissions

    @LazyProperty
    def user_group_permissions(self):
        log.debug('Getting user group permissions for %s', self)
        user_group_permissions = {}
        default_user_group_perms = db.Permission.get_default_user_group_perms(kallithea.DEFAULT_USER_ID)

        if self.is_admin:
            for perm in default_user_group_perms:
                u_k = perm.user_group.users_group_name
                p = 'usergroup.admin'
                user_group_permissions[u_k] = p

        else:
            # defaults for user groups taken from default user permission
            # on given user group
            for perm in default_user_group_perms:
                u_k = perm.user_group.users_group_name
                p = perm.permission.permission_name
                user_group_permissions[u_k] = p

            # user group for user group permissions
            user_group_user_groups_perms = \
                meta.Session().query(db.UserGroupUserGroupToPerm) \
                .join((db.UserGroup, db.UserGroupUserGroupToPerm.target_user_group_id
                       == db.UserGroup.users_group_id)) \
                .join((db.UserGroupMember, db.UserGroupUserGroupToPerm.user_group_id
                       == db.UserGroupMember.users_group_id)) \
                .filter(db.UserGroupMember.user_id == self.user_id) \
                .join((db.UserGroup, db.UserGroupMember.users_group_id ==
                       db.UserGroup.users_group_id), aliased=True, from_joinpoint=True) \
                .filter(db.UserGroup.users_group_active == True) \
                .options(joinedload(db.UserGroupUserGroupToPerm.permission)) \
                .all()
            for perm in user_group_user_groups_perms:
                bump_permission(user_group_permissions,
                    perm.target_user_group.users_group_name,
                    perm.permission.permission_name)

            # user explicit permission for user groups
            user_user_groups_perms = db.Permission.get_default_user_group_perms(self.user_id)
            for perm in user_user_groups_perms:
                bump_permission(user_group_permissions,
                    perm.user_group.users_group_name,
                    perm.permission.permission_name)

        return user_group_permissions

    @LazyProperty
    def permissions(self):
        """dict with all 4 kind of permissions - mainly for backwards compatibility"""
        return {
            'global': self.global_permissions,
            'repositories': self.repository_permissions,
            'repositories_groups': self.repository_group_permissions,
            'user_groups': self.user_group_permissions,
        }

    def has_repository_permission_level(self, repo_name, level, purpose=None):
        required_perms = {
            'read': ['repository.read', 'repository.write', 'repository.admin'],
            'write': ['repository.write', 'repository.admin'],
            'admin': ['repository.admin'],
        }[level]
        actual_perm = self.repository_permissions.get(repo_name)
        ok = actual_perm in required_perms
        log.debug('Checking if user %r can %r repo %r (%s): %s (has %r)',
            self.username, level, repo_name, purpose, ok, actual_perm)
        return ok

    def has_repository_group_permission_level(self, repo_group_name, level, purpose=None):
        required_perms = {
            'read': ['group.read', 'group.write', 'group.admin'],
            'write': ['group.write', 'group.admin'],
            'admin': ['group.admin'],
        }[level]
        actual_perm = self.repository_group_permissions.get(repo_group_name)
        ok = actual_perm in required_perms
        log.debug('Checking if user %r can %r repo group %r (%s): %s (has %r)',
            self.username, level, repo_group_name, purpose, ok, actual_perm)
        return ok

    def has_user_group_permission_level(self, user_group_name, level, purpose=None):
        required_perms = {
            'read': ['usergroup.read', 'usergroup.write', 'usergroup.admin'],
            'write': ['usergroup.write', 'usergroup.admin'],
            'admin': ['usergroup.admin'],
        }[level]
        actual_perm = self.user_group_permissions.get(user_group_name)
        ok = actual_perm in required_perms
        log.debug('Checking if user %r can %r user group %r (%s): %s (has %r)',
            self.username, level, user_group_name, purpose, ok, actual_perm)
        return ok

    @property
    def api_keys(self):
        return self._get_api_keys()

    def _get_api_keys(self):
        api_keys = [self.api_key]
        for api_key in db.UserApiKeys.query() \
                .filter_by(user_id=self.user_id, is_expired=False):
            api_keys.append(api_key.api_key)

        return api_keys

    @property
    def is_admin(self):
        return self.admin

    @property
    def repositories_admin(self):
        """
        Returns list of repositories you're an admin of
        """
        return [x[0] for x in self.repository_permissions.items()
                if x[1] == 'repository.admin']

    @property
    def repository_groups_admin(self):
        """
        Returns list of repository groups you're an admin of
        """
        return [x[0] for x in self.repository_group_permissions.items()
                if x[1] == 'group.admin']

    @property
    def user_groups_admin(self):
        """
        Returns list of user groups you're an admin of
        """
        return [x[0] for x in self.user_group_permissions.items()
                if x[1] == 'usergroup.admin']

    def __repr__(self):
        return "<%s %s: %r>" % (self.__class__.__name__, self.user_id, self.username)

    def to_cookie(self):
        """ Serializes this login session to a cookie `dict`. """
        return {
            'user_id': self.user_id,
            'is_external_auth': self.is_external_auth,
        }

    @staticmethod
    def from_cookie(cookie, ip_addr):
        """
        Deserializes an `AuthUser` from a cookie `dict` ... or return None.
        """
        return AuthUser.make(
            dbuser=UserModel().get(cookie.get('user_id')),
            is_external_auth=cookie.get('is_external_auth', False),
            ip_addr=ip_addr,
        )

    @classmethod
    def get_allowed_ips(cls, user_id):
        _set = set()

        default_ips = db.UserIpMap.query().filter(db.UserIpMap.user_id == kallithea.DEFAULT_USER_ID)
        for ip in default_ips:
            try:
                _set.add(ip.ip_addr)
            except ObjectDeletedError:
                # since we use heavy caching sometimes it happens that we get
                # deleted objects here, we just skip them
                pass

        user_ips = db.UserIpMap.query().filter(db.UserIpMap.user_id == user_id)
        for ip in user_ips:
            try:
                _set.add(ip.ip_addr)
            except ObjectDeletedError:
                # since we use heavy caching sometimes it happens that we get
                # deleted objects here, we just skip them
                pass
        return _set or set(['0.0.0.0/0', '::/0'])

    def get_all_user_repos(self):
        """
        Gets all repositories that user have at least read access
        """
        repos = [repo_name
            for repo_name, perm in self.repository_permissions.items()
            if perm in ['repository.read', 'repository.write', 'repository.admin']
            ]
        return db.Repository.query().filter(db.Repository.repo_name.in_(repos))


#==============================================================================
# CHECK DECORATORS
#==============================================================================

def _redirect_to_login(message=None):
    """Return an exception that must be raised. It will redirect to the login
    page which will redirect back to the current URL after authentication.
    The optional message will be shown in a flash message."""
    if message:
        webutils.flash(message, category='warning')
    p = request.path_qs
    log.debug('Redirecting to login page, origin: %s', p)
    return HTTPFound(location=url('login_home', came_from=p))


# Use as decorator
class LoginRequired(object):
    """Client must be logged in as a valid User, or we'll redirect to the login
    page.

    If the "default" user is enabled and allow_default_user is true, that is
    considered valid too.

    Also checks that IP address is allowed.
    """

    def __init__(self, allow_default_user=False):
        self.allow_default_user = allow_default_user

    def __call__(self, func):
        return decorator(self.__wrapper, func)

    def __wrapper(self, func, *fargs, **fkwargs):
        controller = fargs[0]
        user = request.authuser
        loc = "%s:%s" % (controller.__class__.__name__, func.__name__)
        log.debug('Checking access for user %s @ %s', user, loc)

        # regular user authentication
        if user.is_default_user:
            if self.allow_default_user:
                log.info('default user @ %s', loc)
                return func(*fargs, **fkwargs)
            log.info('default user is redirected to login @ %s', loc)
        elif user.is_anonymous: # default user is disabled and no proper authentication
            log.info('anonymous user is redirected to login @ %s', loc)
        else: # regular authentication
            log.info('user %s authenticated with regular auth @ %s', user, loc)
            return func(*fargs, **fkwargs)
        raise _redirect_to_login()


# Use as decorator
class NotAnonymous(object):
    """Ensures that client is not logged in as the "default" user, and
    redirects to the login page otherwise. Must be used together with
    LoginRequired."""

    def __call__(self, func):
        return decorator(self.__wrapper, func)

    def __wrapper(self, func, *fargs, **fkwargs):
        cls = fargs[0]
        user = request.authuser

        log.debug('Checking that user %s is not anonymous @%s', user.username, cls)

        if user.is_default_user:
            raise _redirect_to_login(_('You need to be a registered user to '
                                       'perform this action'))
        else:
            return func(*fargs, **fkwargs)


class _PermsDecorator(object):
    """Base class for controller decorators with multiple permissions"""

    def __init__(self, *required_perms):
        self.required_perms = required_perms # usually very short - a list is thus fine

    def __call__(self, func):
        return decorator(self.__wrapper, func)

    def __wrapper(self, func, *fargs, **fkwargs):
        cls = fargs[0]
        user = request.authuser
        log.debug('checking %s permissions %s for %s %s',
          self.__class__.__name__, self.required_perms, cls, user)

        if self.check_permissions(user):
            log.debug('Permission granted for %s %s', cls, user)
            return func(*fargs, **fkwargs)

        else:
            log.info('Permission denied for %s %s', cls, user)
            if user.is_default_user:
                raise _redirect_to_login(_('You need to be signed in to view this page'))
            else:
                raise HTTPForbidden()

    def check_permissions(self, user):
        raise NotImplementedError()


class HasPermissionAnyDecorator(_PermsDecorator):
    """
    Checks the user has any of the given global permissions.
    """

    def check_permissions(self, user):
        return any(p in user.global_permissions for p in self.required_perms)


class _PermDecorator(_PermsDecorator):
    """Base class for controller decorators with a single permission"""

    def __init__(self, required_perm):
        _PermsDecorator.__init__(self, [required_perm])
        self.required_perm = required_perm


class HasRepoPermissionLevelDecorator(_PermDecorator):
    """
    Checks the user has at least the specified permission level for the requested repository.
    """

    def check_permissions(self, user):
        repo_name = get_repo_slug(request)
        return user.has_repository_permission_level(repo_name, self.required_perm)


class HasRepoGroupPermissionLevelDecorator(_PermDecorator):
    """
    Checks the user has any of given permissions for the requested repository group.
    """

    def check_permissions(self, user):
        repo_group_name = get_repo_group_slug(request)
        return user.has_repository_group_permission_level(repo_group_name, self.required_perm)


class HasUserGroupPermissionLevelDecorator(_PermDecorator):
    """
    Checks for access permission for any of given predicates for specific
    user group. In order to fulfill the request any of predicates must be meet
    """

    def check_permissions(self, user):
        user_group_name = get_user_group_slug(request)
        return user.has_user_group_permission_level(user_group_name, self.required_perm)


#==============================================================================
# CHECK FUNCTIONS
#==============================================================================

class _PermsFunction(object):
    """Base function for other check functions with multiple permissions"""

    def __init__(self, *required_perms):
        self.required_perms = required_perms # usually very short - a list is thus fine

    def __bool__(self):
        """ Defend against accidentally forgetting to call the object
            and instead evaluating it directly in a boolean context,
            which could have security implications.
        """
        raise AssertionError(self.__class__.__name__ + ' is not a bool and must be called!')

    def __call__(self, *a, **b):
        raise NotImplementedError()


class HasPermissionAny(_PermsFunction):

    def __call__(self, purpose=None):
        ok = any(p in request.authuser.global_permissions for p in self.required_perms)

        log.debug('Check %s for global %s (%s): %s',
            request.authuser.username, self.required_perms, purpose, ok)
        return ok


class _PermFunction(_PermsFunction):
    """Base function for other check functions with a single permission"""

    def __init__(self, required_perm):
        _PermsFunction.__init__(self, [required_perm])
        self.required_perm = required_perm


class HasRepoPermissionLevel(_PermFunction):

    def __call__(self, repo_name, purpose=None):
        return request.authuser.has_repository_permission_level(repo_name, self.required_perm, purpose)


class HasRepoGroupPermissionLevel(_PermFunction):

    def __call__(self, group_name, purpose=None):
        return request.authuser.has_repository_group_permission_level(group_name, self.required_perm, purpose)


class HasUserGroupPermissionLevel(_PermFunction):

    def __call__(self, user_group_name, purpose=None):
        return request.authuser.has_user_group_permission_level(user_group_name, self.required_perm, purpose)


#==============================================================================
# SPECIAL VERSION TO HANDLE MIDDLEWARE AUTH
#==============================================================================

class HasPermissionAnyMiddleware(object):
    def __init__(self, *perms):
        self.required_perms = set(perms)

    def __call__(self, authuser, repo_name, purpose=None):
        try:
            ok = authuser.repository_permissions[repo_name] in self.required_perms
        except KeyError:
            ok = False

        log.debug('Middleware check %s for %s for repo %s (%s): %s', authuser.username, self.required_perms, repo_name, purpose, ok)
        return ok


def check_ip_access(source_ip, allowed_ips=None):
    """
    Checks if source_ip is a subnet of any of allowed_ips.

    :param source_ip:
    :param allowed_ips: list of allowed ips together with mask
    """
    source_ip = source_ip.split('%', 1)[0]
    log.debug('checking if ip:%s is subnet of %s', source_ip, allowed_ips)
    if isinstance(allowed_ips, (tuple, list, set)):
        for ip in allowed_ips:
            if ipaddr.IPAddress(source_ip) in ipaddr.IPNetwork(ip):
                log.debug('IP %s is network %s',
                          ipaddr.IPAddress(source_ip), ipaddr.IPNetwork(ip))
                return True
    return False
