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
kallithea.model.user
~~~~~~~~~~~~~~~~~~~~

users model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 9, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import hashlib
import hmac
import logging
import time
import traceback

from sqlalchemy.exc import DatabaseError
from tg import config
from tg.i18n import ugettext as _

from kallithea.lib import hooks, webutils
from kallithea.lib.exceptions import DefaultUserException, UserOwnsReposException
from kallithea.lib.utils2 import check_password, generate_api_key, get_crypt_password, get_current_authuser
from kallithea.model import db, forms, meta, notification


log = logging.getLogger(__name__)


class UserModel(object):
    password_reset_token_lifetime = 86400 # 24 hours

    def get(self, user_id):
        user = db.User.query()
        return user.get(user_id)

    def get_user(self, user):
        return db.User.guess_instance(user)

    def create(self, form_data, cur_user=None):
        if not cur_user:
            cur_user = getattr(get_current_authuser(), 'username', None)

        _fd = form_data
        user_data = {
            'username': _fd['username'],
            'password': _fd['password'],
            'email': _fd['email'],
            'firstname': _fd['firstname'],
            'lastname': _fd['lastname'],
            'active': _fd['active'],
            'admin': False
        }
        # raises UserCreationError if it's not allowed
        hooks.check_allowed_create_user(user_data, cur_user)

        new_user = db.User()
        for k, v in form_data.items():
            if k == 'password':
                v = get_crypt_password(v)
            if k == 'firstname':
                k = 'name'
            setattr(new_user, k, v)

        new_user.api_key = generate_api_key()
        meta.Session().add(new_user)
        meta.Session().flush() # make database assign new_user.user_id

        hooks.log_create_user(new_user.get_dict(), cur_user)
        return new_user

    def create_or_update(self, username, password, email, firstname='',
                         lastname='', active=True, admin=False,
                         extern_type=None, extern_name=None, cur_user=None):
        """
        Creates a new instance if not found, or updates current one

        :param username:
        :param password:
        :param email:
        :param active:
        :param firstname:
        :param lastname:
        :param active:
        :param admin:
        :param extern_name:
        :param extern_type:
        :param cur_user:
        """
        if not cur_user:
            cur_user = getattr(get_current_authuser(), 'username', None)

        user_data = {
            'username': username, 'password': password,
            'email': email, 'firstname': firstname, 'lastname': lastname,
            'active': active, 'admin': admin
        }
        # raises UserCreationError if it's not allowed
        hooks.check_allowed_create_user(user_data, cur_user)

        log.debug('Checking for %s account in Kallithea database', username)
        user = db.User.get_by_username(username, case_insensitive=True)
        if user is None:
            log.debug('creating new user %s', username)
            new_user = db.User()
            edit = False
        else:
            log.debug('updating user %s', username)
            new_user = user
            edit = True

        try:
            new_user.username = username
            new_user.admin = admin
            new_user.email = email
            new_user.active = active
            new_user.extern_name = extern_name
            new_user.extern_type = extern_type
            new_user.name = firstname
            new_user.lastname = lastname

            if not edit:
                new_user.api_key = generate_api_key()

            # set password only if creating an user or password is changed
            password_change = new_user.password and \
                not check_password(password, new_user.password)
            if not edit or password_change:
                reason = 'new password' if edit else 'new user'
                log.debug('Updating password reason=>%s', reason)
                new_user.password = get_crypt_password(password) \
                    if password else ''

            if user is None:
                meta.Session().add(new_user)
                meta.Session().flush() # make database assign new_user.user_id

            if not edit:
                hooks.log_create_user(new_user.get_dict(), cur_user)

            return new_user
        except (DatabaseError,):
            log.error(traceback.format_exc())
            raise

    def create_registration(self, form_data):
        form_data['admin'] = False
        form_data['extern_type'] = db.User.DEFAULT_AUTH_TYPE
        form_data['extern_name'] = ''
        new_user = self.create(form_data)

        # notification to admins
        edit_url = webutils.canonical_url('edit_user', id=new_user.user_id)
        email_kwargs = {
            'registered_user_url': edit_url,
            'new_username': new_user.username,
            'new_email': new_user.email,
            'new_full_name': new_user.full_name}
        notification.NotificationModel().create(created_by=new_user,
                                   body=None, recipients=None,
                                   type_=notification.NotificationModel.TYPE_REGISTRATION,
                                   email_kwargs=email_kwargs)

    def update(self, user_id, form_data, skip_attrs=None):
        skip_attrs = skip_attrs or []
        user = self.get(user_id)
        if user.is_default_user:
            raise DefaultUserException(
                            _("You can't edit this user since it's "
                              "crucial for entire application"))

        for k, v in form_data.items():
            if k in skip_attrs:
                continue
            if k == 'new_password' and v:
                user.password = get_crypt_password(v)
            else:
                # old legacy thing orm models store firstname as name,
                # need proper refactor to username
                if k == 'firstname':
                    k = 'name'
                setattr(user, k, v)

    def update_user(self, user, **kwargs):
        user = db.User.guess_instance(user)
        if user.is_default_user:
            raise DefaultUserException(
                _("You can't edit this user since it's"
                  " crucial for entire application")
            )

        for k, v in kwargs.items():
            if k == 'password' and v:
                v = get_crypt_password(v)

            setattr(user, k, v)
        return user

    def delete(self, user, cur_user=None):
        if cur_user is None:
            cur_user = getattr(get_current_authuser(), 'username', None)
        user = db.User.guess_instance(user)

        if user.is_default_user:
            raise DefaultUserException(
                _("You can't remove this user since it is"
                  " crucial for the entire application"))
        if user.repositories:
            repos = [x.repo_name for x in user.repositories]
            raise UserOwnsReposException(
                _('User "%s" still owns %s repositories and cannot be '
                  'removed. Switch owners or remove those repositories: %s')
                % (user.username, len(repos), ', '.join(repos)))
        if user.repo_groups:
            repogroups = [x.group_name for x in user.repo_groups]
            raise UserOwnsReposException(_(
                'User "%s" still owns %s repository groups and cannot be '
                'removed. Switch owners or remove those repository groups: %s')
                % (user.username, len(repogroups), ', '.join(repogroups)))
        if user.user_groups:
            usergroups = [x.users_group_name for x in user.user_groups]
            raise UserOwnsReposException(
                _('User "%s" still owns %s user groups and cannot be '
                  'removed. Switch owners or remove those user groups: %s')
                % (user.username, len(usergroups), ', '.join(usergroups)))
        meta.Session().delete(user)

        hooks.log_delete_user(user.get_dict(), cur_user)

    def can_change_password(self, user):
        from kallithea.lib import auth_modules
        managed_fields = auth_modules.get_managed_fields(user)
        return 'password' not in managed_fields

    def get_reset_password_token(self, user, timestamp, session_id):
        """
        The token is a 40-digit hexstring, calculated as a HMAC-SHA1.

        In a traditional HMAC scenario, an attacker is unable to know or
        influence the secret key, but can know or influence the message
        and token. This scenario is slightly different (in particular
        since the message sender is also the message recipient), but
        sufficiently similar to use an HMAC. Benefits compared to a plain
        SHA1 hash includes resistance against a length extension attack.

        The HMAC key consists of the following values (known only to the
        server and authorized users):

        * per-application secret (the `app_instance_uuid` setting), without
          which an attacker cannot counterfeit tokens
        * hashed user password, invalidating the token upon password change

        The HMAC message consists of the following values (potentially known
        to an attacker):

        * session ID (the anti-CSRF token), requiring an attacker to have
          access to the browser session in which the token was created
        * numeric user ID, limiting the token to a specific user (yet allowing
          users to be renamed)
        * user email address
        * time of token issue (a Unix timestamp, to enable token expiration)

        The key and message values are separated by NUL characters, which are
        guaranteed not to occur in any of the values.
        """
        app_secret = config.get('app_instance_uuid')
        return hmac.new(
            '\0'.join([app_secret, user.password]).encode('utf-8'),
            msg='\0'.join([session_id, str(user.user_id), user.email, str(timestamp)]).encode('utf-8'),
            digestmod=hashlib.sha1,
        ).hexdigest()

    def send_reset_password_email(self, data):
        """
        Sends email with a password reset token and link to the password
        reset confirmation page with all information (including the token)
        pre-filled. Also returns URL of that page, only without the token,
        allowing users to copy-paste or manually enter the token from the
        email.
        """
        user_email = data['email']
        user = db.User.get_by_email(user_email)
        timestamp = int(time.time())
        if user is not None:
            if self.can_change_password(user):
                log.debug('password reset user %s found', user)
                token = self.get_reset_password_token(user,
                                                      timestamp,
                                                      webutils.session_csrf_secret_token())
                # URL must be fully qualified; but since the token is locked to
                # the current browser session, we must provide a URL with the
                # current scheme and hostname, rather than the canonical_url.
                link = webutils.url('reset_password_confirmation', qualified=True,
                             email=user_email,
                             timestamp=timestamp,
                             token=token)
            else:
                log.debug('password reset user %s found but was managed', user)
                token = link = None
            reg_type = notification.EmailNotificationModel.TYPE_PASSWORD_RESET
            body = notification.EmailNotificationModel().get_email_tmpl(
                reg_type, 'txt',
                user=user.short_contact,
                reset_token=token,
                reset_url=link)
            html_body = notification.EmailNotificationModel().get_email_tmpl(
                reg_type, 'html',
                user=user.short_contact,
                reset_token=token,
                reset_url=link)
            log.debug('sending email')
            notification.send_email([user_email], _("Password reset link"), body, html_body)
            log.info('send new password mail to %s', user_email)
        else:
            log.debug("password reset email %s not found", user_email)

        return webutils.url('reset_password_confirmation',
                     email=user_email,
                     timestamp=timestamp)

    def verify_reset_password_token(self, email, timestamp, token):
        user = db.User.get_by_email(email)
        if user is None:
            log.debug("user with email %s not found", email)
            return False

        token_age = int(time.time()) - int(timestamp)

        if token_age < 0:
            log.debug('timestamp is from the future')
            return False

        if token_age > UserModel.password_reset_token_lifetime:
            log.debug('password reset token expired')
            return False

        expected_token = self.get_reset_password_token(user,
                                                       timestamp,
                                                       webutils.session_csrf_secret_token())
        log.debug('computed password reset token: %s', expected_token)
        log.debug('received password reset token: %s', token)
        return expected_token == token

    def reset_password(self, user_email, new_passwd):
        user = db.User.get_by_email(user_email)
        if user is not None:
            if not self.can_change_password(user):
                raise Exception('trying to change password for external user')
            user.password = get_crypt_password(new_passwd)
            meta.Session().commit()
            log.info('change password for %s', user_email)
        if new_passwd is None:
            raise Exception('unable to set new password')

        notification.send_email([user_email],
                 _('Password reset notification'),
                 _('The password to your account %s has been changed using password reset form.') % (user.username,))
        log.info('send password reset mail to %s', user_email)

        return True

    def has_perm(self, user, perm):
        perm = db.Permission.guess_instance(perm)
        user = db.User.guess_instance(user)

        return db.UserToPerm.query().filter(db.UserToPerm.user == user) \
            .filter(db.UserToPerm.permission == perm).scalar() is not None

    def grant_perm(self, user, perm):
        """
        Grant user global permissions

        :param user:
        :param perm:
        """
        user = db.User.guess_instance(user)
        perm = db.Permission.guess_instance(perm)
        # if this permission is already granted skip it
        _perm = db.UserToPerm.query() \
            .filter(db.UserToPerm.user == user) \
            .filter(db.UserToPerm.permission == perm) \
            .scalar()
        if _perm:
            return
        new = db.UserToPerm()
        new.user = user
        new.permission = perm
        meta.Session().add(new)
        return new

    def revoke_perm(self, user, perm):
        """
        Revoke users global permissions

        :param user:
        :param perm:
        """
        user = db.User.guess_instance(user)
        perm = db.Permission.guess_instance(perm)

        db.UserToPerm.query().filter(
            db.UserToPerm.user == user,
            db.UserToPerm.permission == perm,
        ).delete()

    def add_extra_email(self, user, email):
        """
        Adds email address to UserEmailMap

        :param user:
        :param email:
        """
        form = forms.UserExtraEmailForm()()
        data = form.to_python(dict(email=email))
        user = db.User.guess_instance(user)

        obj = db.UserEmailMap()
        obj.user = user
        obj.email = data['email']
        meta.Session().add(obj)
        return obj

    def delete_extra_email(self, user, email_id):
        """
        Removes email address from UserEmailMap

        :param user:
        :param email_id:
        """
        user = db.User.guess_instance(user)
        obj = db.UserEmailMap.query().get(email_id)
        if obj is not None:
            meta.Session().delete(obj)

    def add_extra_ip(self, user, ip):
        """
        Adds IP address to UserIpMap

        :param user:
        :param ip:
        """
        form = forms.UserExtraIpForm()()
        data = form.to_python(dict(ip=ip))
        user = db.User.guess_instance(user)

        obj = db.UserIpMap()
        obj.user = user
        obj.ip_addr = data['ip']
        meta.Session().add(obj)
        return obj

    def delete_extra_ip(self, user, ip_id):
        """
        Removes IP address from UserIpMap

        :param user:
        :param ip_id:
        """
        user = db.User.guess_instance(user)
        obj = db.UserIpMap.query().get(ip_id)
        if obj:
            meta.Session().delete(obj)
