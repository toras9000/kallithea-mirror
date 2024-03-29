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
kallithea.controllers.admin.permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

permissions controller for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 27, 2010
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
from kallithea.lib import webutils
from kallithea.lib.auth import AuthUser, HasPermissionAnyDecorator, LoginRequired
from kallithea.lib.webutils import url
from kallithea.model import db, meta
from kallithea.model.forms import DefaultPermissionsForm
from kallithea.model.permission import PermissionModel


log = logging.getLogger(__name__)


class PermissionsController(base.BaseController):

    @LoginRequired()
    @HasPermissionAnyDecorator('hg.admin')
    def _before(self, *args, **kwargs):
        super(PermissionsController, self)._before(*args, **kwargs)

    def __load_data(self):
        # Permissions for the Default user on new repositories
        c.repo_perms_choices = [('repository.none', _('None'),),
                                   ('repository.read', _('Read'),),
                                   ('repository.write', _('Write'),),
                                   ('repository.admin', _('Admin'),)]
        # Permissions for the Default user on new repository groups
        c.group_perms_choices = [('group.none', _('None'),),
                                 ('group.read', _('Read'),),
                                 ('group.write', _('Write'),),
                                 ('group.admin', _('Admin'),)]
        # Permissions for the Default user on new user groups
        c.user_group_perms_choices = [('usergroup.none', _('None'),),
                                      ('usergroup.read', _('Read'),),
                                      ('usergroup.write', _('Write'),),
                                      ('usergroup.admin', _('Admin'),)]
        # Registration - allow new Users to create an account
        c.register_choices = [
            ('hg.register.none',
                _('Disabled')),
            ('hg.register.manual_activate',
                _('Allowed with manual account activation')),
            ('hg.register.auto_activate',
                _('Allowed with automatic account activation')), ]
        # External auth account activation
        c.extern_activate_choices = [
            ('hg.extern_activate.manual', _('Manual activation of external account')),
            ('hg.extern_activate.auto', _('Automatic activation of external account')),
        ]
        # Top level repository creation
        c.repo_create_choices = [('hg.create.none', _('Disabled')),
                                 ('hg.create.repository', _('Enabled'))]
        # User group creation
        c.user_group_create_choices = [('hg.usergroup.create.false', _('Disabled')),
                                       ('hg.usergroup.create.true', _('Enabled'))]
        # Repository forking:
        c.fork_choices = [('hg.fork.none', _('Disabled')),
                          ('hg.fork.repository', _('Enabled'))]

    def permission_globals(self):
        c.active = 'globals'
        self.__load_data()
        if request.POST:
            _form = DefaultPermissionsForm(
                [x[0] for x in c.repo_perms_choices],
                [x[0] for x in c.group_perms_choices],
                [x[0] for x in c.user_group_perms_choices],
                [x[0] for x in c.repo_create_choices],
                [x[0] for x in c.user_group_create_choices],
                [x[0] for x in c.fork_choices],
                [x[0] for x in c.register_choices],
                [x[0] for x in c.extern_activate_choices])()

            try:
                form_result = _form.to_python(dict(request.POST))
                form_result.update({'perm_user_name': 'default'})
                PermissionModel().update(form_result)
                meta.Session().commit()
                webutils.flash(_('Global permissions updated successfully'),
                        category='success')

            except formencode.Invalid as errors:
                defaults = errors.value

                return htmlfill.render(
                    base.render('admin/permissions/permissions.html'),
                    defaults=defaults,
                    errors=errors.error_dict or {},
                    prefix_error=False,
                    encoding="UTF-8",
                    force_defaults=False)
            except Exception:
                log.error(traceback.format_exc())
                webutils.flash(_('Error occurred during update of permissions'),
                        category='error')

            raise HTTPFound(location=url('admin_permissions'))

        c.user = db.User.get_default_user()
        defaults = {'anonymous': c.user.active}

        for p in c.user.user_perms:
            if p.permission.permission_name.startswith('repository.'):
                defaults['default_repo_perm'] = p.permission.permission_name

            if p.permission.permission_name.startswith('group.'):
                defaults['default_group_perm'] = p.permission.permission_name

            if p.permission.permission_name.startswith('usergroup.'):
                defaults['default_user_group_perm'] = p.permission.permission_name

            elif p.permission.permission_name.startswith('hg.create.'):
                defaults['default_repo_create'] = p.permission.permission_name

            if p.permission.permission_name.startswith('hg.usergroup.'):
                defaults['default_user_group_create'] = p.permission.permission_name

            if p.permission.permission_name.startswith('hg.register.'):
                defaults['default_register'] = p.permission.permission_name

            if p.permission.permission_name.startswith('hg.extern_activate.'):
                defaults['default_extern_activate'] = p.permission.permission_name

            if p.permission.permission_name.startswith('hg.fork.'):
                defaults['default_fork'] = p.permission.permission_name

        return htmlfill.render(
            base.render('admin/permissions/permissions.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    def permission_ips(self):
        c.active = 'ips'
        c.user = db.User.get_default_user()
        c.user_ip_map = db.UserIpMap.query() \
                        .filter(db.UserIpMap.user == c.user).all()

        return base.render('admin/permissions/permissions.html')

    def permission_perms(self):
        c.active = 'perms'
        c.user = db.User.get_default_user()
        c.perm_user = AuthUser(dbuser=c.user)
        return base.render('admin/permissions/permissions.html')
