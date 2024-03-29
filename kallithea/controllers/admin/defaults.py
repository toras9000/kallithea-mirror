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
kallithea.controllers.admin.defaults
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

default settings controller for Kallithea

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
from tg.i18n import ugettext as _
from webob.exc import HTTPFound

from kallithea.controllers import base
from kallithea.lib import webutils
from kallithea.lib.auth import HasPermissionAnyDecorator, LoginRequired
from kallithea.lib.webutils import url
from kallithea.model import db, meta
from kallithea.model.forms import DefaultsForm


log = logging.getLogger(__name__)


class DefaultsController(base.BaseController):

    @LoginRequired()
    @HasPermissionAnyDecorator('hg.admin')
    def _before(self, *args, **kwargs):
        super(DefaultsController, self)._before(*args, **kwargs)

    def index(self, format='html'):
        defaults = db.Setting.get_default_repo_settings()

        return htmlfill.render(
            base.render('admin/defaults/defaults.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False
        )

    def update(self, id):
        _form = DefaultsForm()()

        try:
            form_result = _form.to_python(dict(request.POST))
            for k, v in form_result.items():
                setting = db.Setting.create_or_update(k, v)
            meta.Session().commit()
            webutils.flash(_('Default settings updated successfully'),
                    category='success')

        except formencode.Invalid as errors:
            defaults = errors.value

            return htmlfill.render(
                base.render('admin/defaults/defaults.html'),
                defaults=defaults,
                errors=errors.error_dict or {},
                prefix_error=False,
                encoding="UTF-8",
                force_defaults=False)
        except Exception:
            log.error(traceback.format_exc())
            webutils.flash(_('Error occurred during update of defaults'),
                    category='error')

        raise HTTPFound(location=url('defaults'))
