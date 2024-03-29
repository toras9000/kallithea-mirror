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
kallithea.controllers.admin.my_account
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

my account controller for Kallithea admin

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: August 20, 2013
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
from webob.exc import HTTPFound

from kallithea.controllers import base
from kallithea.lib import auth_modules, webutils
from kallithea.lib.auth import AuthUser, LoginRequired
from kallithea.lib.utils2 import generate_api_key, safe_int
from kallithea.lib.webutils import url
from kallithea.model import db, meta
from kallithea.model.api_key import ApiKeyModel
from kallithea.model.forms import PasswordChangeForm, UserForm
from kallithea.model.repo import RepoModel
from kallithea.model.ssh_key import SshKeyModel, SshKeyModelException
from kallithea.model.user import UserModel


log = logging.getLogger(__name__)


class MyAccountController(base.BaseController):

    @LoginRequired()
    def _before(self, *args, **kwargs):
        super(MyAccountController, self)._before(*args, **kwargs)

    def __load_data(self):
        c.user = db.User.get(request.authuser.user_id)
        if c.user.is_default_user:
            webutils.flash(_("You can't edit this user since it's"
                      " crucial for entire application"), category='warning')
            raise HTTPFound(location=url('users'))

    def _load_my_repos_data(self, watched=False):
        if watched:
            admin = False
            repos_list = meta.Session().query(db.Repository) \
                         .join(db.UserFollowing) \
                         .filter(db.UserFollowing.user_id ==
                                 request.authuser.user_id).all()
        else:
            admin = True
            repos_list = meta.Session().query(db.Repository) \
                         .filter(db.Repository.owner_id ==
                                 request.authuser.user_id).all()

        return RepoModel().get_repos_as_dict(repos_list, admin=admin)

    def my_account(self):
        c.active = 'profile'
        self.__load_data()
        c.perm_user = AuthUser(user_id=request.authuser.user_id)
        managed_fields = auth_modules.get_managed_fields(c.user)
        def_user_perms = AuthUser(dbuser=db.User.get_default_user()).global_permissions
        if 'hg.register.none' in def_user_perms:
            managed_fields.extend(['username', 'firstname', 'lastname', 'email'])

        c.readonly = lambda n: 'readonly' if n in managed_fields else None

        defaults = c.user.get_dict()
        update = False
        if request.POST:
            _form = UserForm(edit=True,
                             old_data={'user_id': request.authuser.user_id,
                                       'email': request.authuser.email})()
            form_result = {}
            try:
                post_data = dict(request.POST)
                post_data['new_password'] = ''
                post_data['password_confirmation'] = ''
                form_result = _form.to_python(post_data)
                # skip updating those attrs for my account
                skip_attrs = ['admin', 'active', 'extern_type', 'extern_name',
                              'new_password', 'password_confirmation',
                             ] + managed_fields

                UserModel().update(request.authuser.user_id, form_result,
                                   skip_attrs=skip_attrs)
                webutils.flash(_('Your account was updated successfully'),
                        category='success')
                meta.Session().commit()
                update = True

            except formencode.Invalid as errors:
                return htmlfill.render(
                    base.render('admin/my_account/my_account.html'),
                    defaults=errors.value,
                    errors=errors.error_dict or {},
                    prefix_error=False,
                    encoding="UTF-8",
                    force_defaults=False)
            except Exception:
                log.error(traceback.format_exc())
                webutils.flash(_('Error occurred during update of user %s')
                        % form_result.get('username'), category='error')
        if update:
            raise HTTPFound(location='my_account')
        return htmlfill.render(
            base.render('admin/my_account/my_account.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    def my_account_password(self):
        c.active = 'password'
        self.__load_data()

        managed_fields = auth_modules.get_managed_fields(c.user)
        c.can_change_password = 'password' not in managed_fields

        if request.POST and c.can_change_password:
            _form = PasswordChangeForm(request.authuser.username)()
            try:
                form_result = _form.to_python(request.POST)
                UserModel().update(request.authuser.user_id, form_result)
                meta.Session().commit()
                webutils.flash(_("Successfully updated password"), category='success')
            except formencode.Invalid as errors:
                return htmlfill.render(
                    base.render('admin/my_account/my_account.html'),
                    defaults=errors.value,
                    errors=errors.error_dict or {},
                    prefix_error=False,
                    encoding="UTF-8",
                    force_defaults=False)
            except Exception:
                log.error(traceback.format_exc())
                webutils.flash(_('Error occurred during update of user password'),
                        category='error')
        return base.render('admin/my_account/my_account.html')

    def my_account_repos(self):
        c.active = 'repos'
        self.__load_data()

        # data used to render the grid
        c.data = self._load_my_repos_data()
        return base.render('admin/my_account/my_account.html')

    def my_account_watched(self):
        c.active = 'watched'
        self.__load_data()

        # data used to render the grid
        c.data = self._load_my_repos_data(watched=True)
        return base.render('admin/my_account/my_account.html')

    def my_account_perms(self):
        c.active = 'perms'
        self.__load_data()
        c.perm_user = AuthUser(user_id=request.authuser.user_id)

        return base.render('admin/my_account/my_account.html')

    def my_account_emails(self):
        c.active = 'emails'
        self.__load_data()

        c.user_email_map = db.UserEmailMap.query() \
            .filter(db.UserEmailMap.user == c.user).all()
        return base.render('admin/my_account/my_account.html')

    def my_account_emails_add(self):
        email = request.POST.get('new_email')

        try:
            UserModel().add_extra_email(request.authuser.user_id, email)
            meta.Session().commit()
            webutils.flash(_("Added email %s to user") % email, category='success')
        except formencode.Invalid as error:
            msg = error.error_dict['email']
            webutils.flash(msg, category='error')
        except Exception:
            log.error(traceback.format_exc())
            webutils.flash(_('An error occurred during email saving'),
                    category='error')
        raise HTTPFound(location=url('my_account_emails'))

    def my_account_emails_delete(self):
        email_id = request.POST.get('del_email_id')
        user_model = UserModel()
        user_model.delete_extra_email(request.authuser.user_id, email_id)
        meta.Session().commit()
        webutils.flash(_("Removed email from user"), category='success')
        raise HTTPFound(location=url('my_account_emails'))

    def my_account_api_keys(self):
        c.active = 'api_keys'
        self.__load_data()
        show_expired = True
        c.lifetime_values = [
            (str(-1), _('Forever')),
            (str(5), _('5 minutes')),
            (str(60), _('1 hour')),
            (str(60 * 24), _('1 day')),
            (str(60 * 24 * 30), _('1 month')),
        ]
        c.lifetime_options = [(c.lifetime_values, _("Lifetime"))]
        c.user_api_keys = ApiKeyModel().get_api_keys(request.authuser.user_id,
                                                     show_expired=show_expired)
        return base.render('admin/my_account/my_account.html')

    def my_account_api_keys_add(self):
        lifetime = safe_int(request.POST.get('lifetime'), -1)
        description = request.POST.get('description')
        ApiKeyModel().create(request.authuser.user_id, description, lifetime)
        meta.Session().commit()
        webutils.flash(_("API key successfully created"), category='success')
        raise HTTPFound(location=url('my_account_api_keys'))

    def my_account_api_keys_delete(self):
        api_key = request.POST.get('del_api_key')
        if request.POST.get('del_api_key_builtin'):
            user = db.User.get(request.authuser.user_id)
            user.api_key = generate_api_key()
            meta.Session().commit()
            webutils.flash(_("API key successfully reset"), category='success')
        elif api_key:
            ApiKeyModel().delete(api_key, request.authuser.user_id)
            meta.Session().commit()
            webutils.flash(_("API key successfully deleted"), category='success')

        raise HTTPFound(location=url('my_account_api_keys'))

    @base.IfSshEnabled
    def my_account_ssh_keys(self):
        c.active = 'ssh_keys'
        self.__load_data()
        c.user_ssh_keys = SshKeyModel().get_ssh_keys(request.authuser.user_id)
        return base.render('admin/my_account/my_account.html')

    @base.IfSshEnabled
    def my_account_ssh_keys_add(self):
        description = request.POST.get('description')
        public_key = request.POST.get('public_key')
        try:
            new_ssh_key = SshKeyModel().create(request.authuser.user_id,
                                               description, public_key)
            meta.Session().commit()
            SshKeyModel().write_authorized_keys()
            webutils.flash(_("SSH key %s successfully added") % new_ssh_key.fingerprint, category='success')
        except SshKeyModelException as e:
            webutils.flash(e.args[0], category='error')
        raise HTTPFound(location=url('my_account_ssh_keys'))

    @base.IfSshEnabled
    def my_account_ssh_keys_delete(self):
        fingerprint = request.POST.get('del_public_key_fingerprint')
        try:
            SshKeyModel().delete(fingerprint, request.authuser.user_id)
            meta.Session().commit()
            SshKeyModel().write_authorized_keys()
            webutils.flash(_("SSH key successfully deleted"), category='success')
        except SshKeyModelException as e:
            webutils.flash(e.args[0], category='error')
        raise HTTPFound(location=url('my_account_ssh_keys'))
