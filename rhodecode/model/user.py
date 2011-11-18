# -*- coding: utf-8 -*-
"""
    rhodecode.model.user
    ~~~~~~~~~~~~~~~~~~~~

    users model for RhodeCode

    :created_on: Apr 9, 2010
    :author: marcink
    :copyright: (C) 2009-2011 Marcin Kuzminski <marcin@python-works.com>
    :license: GPLv3, see COPYING for more details.
"""
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

import logging
import traceback

from pylons.i18n.translation import _

from rhodecode.lib import safe_unicode
from rhodecode.lib.caching_query import FromCache

from rhodecode.model import BaseModel
from rhodecode.model.db import User, UserRepoToPerm, Repository, Permission, \
    UserToPerm, UsersGroupRepoToPerm, UsersGroupToPerm, UsersGroupMember
from rhodecode.lib.exceptions import DefaultUserException, \
    UserOwnsReposException

from sqlalchemy.exc import DatabaseError
from rhodecode.lib import generate_api_key
from sqlalchemy.orm import joinedload

log = logging.getLogger(__name__)

PERM_WEIGHTS = {'repository.none': 0,
                'repository.read': 1,
                'repository.write': 3,
                'repository.admin': 3}


class UserModel(BaseModel):
    def get(self, user_id, cache=False):
        user = self.sa.query(User)
        if cache:
            user = user.options(FromCache("sql_cache_short",
                                          "get_user_%s" % user_id))
        return user.get(user_id)

    def get_by_username(self, username, cache=False, case_insensitive=False):

        if case_insensitive:
            user = self.sa.query(User).filter(User.username.ilike(username))
        else:
            user = self.sa.query(User)\
                .filter(User.username == username)
        if cache:
            user = user.options(FromCache("sql_cache_short",
                                          "get_user_%s" % username))
        return user.scalar()

    def get_by_api_key(self, api_key, cache=False):
        return User.get_by_api_key(api_key, cache)

    def create(self, form_data):
        try:
            new_user = User()
            for k, v in form_data.items():
                setattr(new_user, k, v)

            new_user.api_key = generate_api_key(form_data['username'])
            self.sa.add(new_user)
            self.sa.commit()
            return new_user
        except:
            log.error(traceback.format_exc())
            self.sa.rollback()
            raise


    def create_or_update(self, username, password, email, name, lastname, 
                         active=True, admin=False, ldap_dn=None):
        """
        Creates a new instance if not found, or updates current one
        
        :param username:
        :param password:
        :param email:
        :param active:
        :param name:
        :param lastname:
        :param active:
        :param admin:
        :param ldap_dn:
        """
        
        from rhodecode.lib.auth import get_crypt_password
        
        log.debug('Checking for %s account in RhodeCode database', username)
        user = User.get_by_username(username, case_insensitive=True)
        if user is None:
            log.debug('creating new user %s', username)            
            new_user = User()
        else:
            log.debug('updating user %s', username)            
            new_user = user
            
        try:
            new_user.username = username
            new_user.admin = admin
            new_user.password = get_crypt_password(password)
            new_user.api_key = generate_api_key(username)
            new_user.email = email
            new_user.active = active
            new_user.ldap_dn = safe_unicode(ldap_dn) if ldap_dn else None
            new_user.name = name
            new_user.lastname = lastname

            self.sa.add(new_user)
            self.sa.commit()
            return new_user
        except (DatabaseError,):
            log.error(traceback.format_exc())
            self.sa.rollback()
            raise
    
    
    def create_for_container_auth(self, username, attrs):
        """
        Creates the given user if it's not already in the database
        
        :param username:
        :param attrs:
        """
        if self.get_by_username(username, case_insensitive=True) is None:

            # autogenerate email for container account without one
            generate_email = lambda usr: '%s@container_auth.account' % usr

            try:
                new_user = User()
                new_user.username = username
                new_user.password = None
                new_user.api_key = generate_api_key(username)
                new_user.email = attrs['email']
                new_user.active = attrs.get('active', True)
                new_user.name = attrs['name'] or generate_email(username)
                new_user.lastname = attrs['lastname']

                self.sa.add(new_user)
                self.sa.commit()
                return new_user
            except (DatabaseError,):
                log.error(traceback.format_exc())
                self.sa.rollback()
                raise
        log.debug('User %s already exists. Skipping creation of account'
                  ' for container auth.', username)
        return None

    def create_ldap(self, username, password, user_dn, attrs):
        """
        Checks if user is in database, if not creates this user marked
        as ldap user
        
        :param username:
        :param password:
        :param user_dn:
        :param attrs:
        """
        from rhodecode.lib.auth import get_crypt_password
        log.debug('Checking for such ldap account in RhodeCode database')
        if self.get_by_username(username, case_insensitive=True) is None:

            # autogenerate email for ldap account without one
            generate_email = lambda usr: '%s@ldap.account' % usr

            try:
                new_user = User()
                username = username.lower()
                # add ldap account always lowercase
                new_user.username = username
                new_user.password = get_crypt_password(password)
                new_user.api_key = generate_api_key(username)
                new_user.email = attrs['email'] or generate_email(username)
                new_user.active = attrs.get('active', True)
                new_user.ldap_dn = safe_unicode(user_dn)
                new_user.name = attrs['name']
                new_user.lastname = attrs['lastname']

                self.sa.add(new_user)
                self.sa.commit()
                return new_user
            except (DatabaseError,):
                log.error(traceback.format_exc())
                self.sa.rollback()
                raise
        log.debug('this %s user exists skipping creation of ldap account',
                  username)
        return None

    def create_registration(self, form_data):
        from rhodecode.lib.celerylib import tasks, run_task
        try:
            new_user = User()
            for k, v in form_data.items():
                if k != 'admin':
                    setattr(new_user, k, v)

            self.sa.add(new_user)
            self.sa.commit()
            body = ('New user registration\n'
                    'username: %s\n'
                    'email: %s\n')
            body = body % (form_data['username'], form_data['email'])

            run_task(tasks.send_email, None,
                     _('[RhodeCode] New User registration'),
                     body)
        except:
            log.error(traceback.format_exc())
            self.sa.rollback()
            raise

    def update(self, user_id, form_data):
        try:
            user = self.get(user_id, cache=False)
            if user.username == 'default':
                raise DefaultUserException(
                                _("You can't Edit this user since it's"
                                  " crucial for entire application"))

            for k, v in form_data.items():
                if k == 'new_password' and v != '':
                    user.password = v
                    user.api_key = generate_api_key(user.username)
                else:
                    setattr(user, k, v)

            self.sa.add(user)
            self.sa.commit()
        except:
            log.error(traceback.format_exc())
            self.sa.rollback()
            raise

    def update_my_account(self, user_id, form_data):
        try:
            user = self.get(user_id, cache=False)
            if user.username == 'default':
                raise DefaultUserException(
                                _("You can't Edit this user since it's"
                                  " crucial for entire application"))
            for k, v in form_data.items():
                if k == 'new_password' and v != '':
                    user.password = v
                    user.api_key = generate_api_key(user.username)
                else:
                    if k not in ['admin', 'active']:
                        setattr(user, k, v)

            self.sa.add(user)
            self.sa.commit()
        except:
            log.error(traceback.format_exc())
            self.sa.rollback()
            raise

    def delete(self, user_id):
        try:
            user = self.get(user_id, cache=False)
            if user.username == 'default':
                raise DefaultUserException(
                                _("You can't remove this user since it's"
                                  " crucial for entire application"))
            if user.repositories:
                raise UserOwnsReposException(_('This user still owns %s '
                                               'repositories and cannot be '
                                               'removed. Switch owners or '
                                               'remove those repositories') \
                                               % user.repositories)
            self.sa.delete(user)
            self.sa.commit()
        except:
            log.error(traceback.format_exc())
            self.sa.rollback()
            raise

    def reset_password_link(self, data):
        from rhodecode.lib.celerylib import tasks, run_task
        run_task(tasks.send_password_link, data['email'])

    def reset_password(self, data):
        from rhodecode.lib.celerylib import tasks, run_task
        run_task(tasks.reset_user_password, data['email'])

    def fill_data(self, auth_user, user_id=None, api_key=None):
        """
        Fetches auth_user by user_id,or api_key if present.
        Fills auth_user attributes with those taken from database.
        Additionally set's is_authenitated if lookup fails
        present in database

        :param auth_user: instance of user to set attributes
        :param user_id: user id to fetch by
        :param api_key: api key to fetch by
        """
        if user_id is None and api_key is None:
            raise Exception('You need to pass user_id or api_key')

        try:
            if api_key:
                dbuser = self.get_by_api_key(api_key)
            else:
                dbuser = self.get(user_id)

            if dbuser is not None and dbuser.active:
                log.debug('filling %s data', dbuser)
                for k, v in dbuser.get_dict().items():
                    setattr(auth_user, k, v)
            else:
                return False

        except:
            log.error(traceback.format_exc())
            auth_user.is_authenticated = False
            return False

        return True

    def fill_perms(self, user):
        """
        Fills user permission attribute with permissions taken from database
        works for permissions given for repositories, and for permissions that
        are granted to groups

        :param user: user instance to fill his perms
        """

        user.permissions['repositories'] = {}
        user.permissions['global'] = set()

        #======================================================================
        # fetch default permissions
        #======================================================================
        default_user = self.get_by_username('default')

        default_perms = self.sa.query(UserRepoToPerm, Repository, Permission)\
            .join((Repository, UserRepoToPerm.repository_id ==
                   Repository.repo_id))\
            .join((Permission, UserRepoToPerm.permission_id ==
                   Permission.permission_id))\
            .filter(UserRepoToPerm.user == default_user).all()

        if user.is_admin:
            #==================================================================
            # #admin have all default rights set to admin
            #==================================================================
            user.permissions['global'].add('hg.admin')

            for perm in default_perms:
                p = 'repository.admin'
                user.permissions['repositories'][perm.UserRepoToPerm.
                                                 repository.repo_name] = p

        else:
            #==================================================================
            # set default permissions
            #==================================================================
            uid = user.user_id

            #default global
            default_global_perms = self.sa.query(UserToPerm)\
                .filter(UserToPerm.user == default_user)

            for perm in default_global_perms:
                user.permissions['global'].add(perm.permission.permission_name)

            #default for repositories
            for perm in default_perms:
                if perm.Repository.private and not (perm.Repository.user_id ==
                                                    uid):
                    #diself.sable defaults for private repos,
                    p = 'repository.none'
                elif perm.Repository.user_id == uid:
                    #set admin if owner
                    p = 'repository.admin'
                else:
                    p = perm.Permission.permission_name

                user.permissions['repositories'][perm.UserRepoToPerm.
                                                 repository.repo_name] = p

            #==================================================================
            # overwrite default with user permissions if any
            #==================================================================

            #user global
            user_perms = self.sa.query(UserToPerm)\
                    .options(joinedload(UserToPerm.permission))\
                    .filter(UserToPerm.user_id == uid).all()

            for perm in user_perms:
                user.permissions['global'].add(perm.permission.
                                               permission_name)

            #user repositories
            user_repo_perms = self.sa.query(UserRepoToPerm, Permission,
                                            Repository)\
                .join((Repository, UserRepoToPerm.repository_id ==
                       Repository.repo_id))\
                .join((Permission, UserRepoToPerm.permission_id ==
                       Permission.permission_id))\
                .filter(UserRepoToPerm.user_id == uid).all()

            for perm in user_repo_perms:
                # set admin if owner
                if perm.Repository.user_id == uid:
                    p = 'repository.admin'
                else:
                    p = perm.Permission.permission_name
                user.permissions['repositories'][perm.UserRepoToPerm.
                                                 repository.repo_name] = p

            #==================================================================
            # check if user is part of groups for this repository and fill in
            # (or replace with higher) permissions
            #==================================================================

            #users group global
            user_perms_from_users_groups = self.sa.query(UsersGroupToPerm)\
                .options(joinedload(UsersGroupToPerm.permission))\
                .join((UsersGroupMember, UsersGroupToPerm.users_group_id ==
                       UsersGroupMember.users_group_id))\
                .filter(UsersGroupMember.user_id == uid).all()

            for perm in user_perms_from_users_groups:
                user.permissions['global'].add(perm.permission.permission_name)

            #users group repositories
            user_repo_perms_from_users_groups = self.sa.query(
                                                UsersGroupRepoToPerm,
                                                Permission, Repository,)\
                .join((Repository, UsersGroupRepoToPerm.repository_id ==
                       Repository.repo_id))\
                .join((Permission, UsersGroupRepoToPerm.permission_id ==
                       Permission.permission_id))\
                .join((UsersGroupMember, UsersGroupRepoToPerm.users_group_id ==
                       UsersGroupMember.users_group_id))\
                .filter(UsersGroupMember.user_id == uid).all()

            for perm in user_repo_perms_from_users_groups:
                p = perm.Permission.permission_name
                cur_perm = user.permissions['repositories'][perm.
                                                    UsersGroupRepoToPerm.
                                                    repository.repo_name]
                #overwrite permission only if it's greater than permission
                # given from other sources
                if PERM_WEIGHTS[p] > PERM_WEIGHTS[cur_perm]:
                    user.permissions['repositories'][perm.UsersGroupRepoToPerm.
                                                     repository.repo_name] = p

        return user

