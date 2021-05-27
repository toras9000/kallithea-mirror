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
kallithea.controllers.admin.settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

settings controller for Kallithea admin

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Jul 14, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
import traceback

import formencode
from formencode import htmlfill
from tg import config, request
from tg import tmpl_context as c
from tg.i18n import ugettext as _
from webob.exc import HTTPFound

import kallithea
import kallithea.lib.indexers.daemon
from kallithea.controllers import base
from kallithea.lib import webutils
from kallithea.lib.auth import HasPermissionAnyDecorator, LoginRequired
from kallithea.lib.utils import repo2db_mapper, set_app_settings
from kallithea.lib.utils2 import safe_str
from kallithea.lib.vcs import VCSError
from kallithea.lib.webutils import url
from kallithea.model import db, meta, notification
from kallithea.model.forms import ApplicationSettingsForm, ApplicationUiSettingsForm, ApplicationVisualisationForm
from kallithea.model.notification import EmailNotificationModel
from kallithea.model.scm import ScmModel


log = logging.getLogger(__name__)


class SettingsController(base.BaseController):

    @LoginRequired(allow_default_user=True)
    def _before(self, *args, **kwargs):
        super(SettingsController, self)._before(*args, **kwargs)

    def _get_hg_ui_settings(self):
        ret = db.Ui.query().all()

        settings = {}
        for each in ret:
            k = each.ui_section + '_' + each.ui_key
            v = each.ui_value
            if k == 'paths_/':
                k = 'paths_root_path'

            k = k.replace('.', '_')

            if each.ui_section in ['hooks', 'extensions']:
                v = each.ui_active

            settings[k] = v
        return settings

    @HasPermissionAnyDecorator('hg.admin')
    def settings_vcs(self):
        c.active = 'vcs'
        if request.POST:
            application_form = ApplicationUiSettingsForm()()
            try:
                form_result = application_form.to_python(dict(request.POST))
            except formencode.Invalid as errors:
                return htmlfill.render(
                     base.render('admin/settings/settings.html'),
                     defaults=errors.value,
                     errors=errors.error_dict or {},
                     prefix_error=False,
                     encoding="UTF-8",
                     force_defaults=False)

            try:
                if c.visual.allow_repo_location_change:
                    sett = db.Ui.get_by_key('paths', '/')
                    sett.ui_value = form_result['paths_root_path']

                # HOOKS
                sett = db.Ui.get_by_key('hooks', db.Ui.HOOK_UPDATE)
                sett.ui_active = form_result['hooks_changegroup_kallithea_update']

                sett = db.Ui.get_by_key('hooks', db.Ui.HOOK_REPO_SIZE)
                sett.ui_active = form_result['hooks_changegroup_kallithea_repo_size']

                ## EXTENSIONS
                sett = db.Ui.get_or_create('extensions', 'largefiles')
                sett.ui_active = form_result['extensions_largefiles']

#                sett = db.Ui.get_or_create('extensions', 'hggit')
#                sett.ui_active = form_result['extensions_hggit']

                meta.Session().commit()

                webutils.flash(_('Updated VCS settings'), category='success')

            except Exception:
                log.error(traceback.format_exc())
                webutils.flash(_('Error occurred while updating '
                          'application settings'), category='error')

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_mapping(self):
        c.active = 'mapping'
        if request.POST:
            rm_obsolete = request.POST.get('destroy', False)
            install_git_hooks = request.POST.get('hooks', False)
            overwrite_git_hooks = request.POST.get('hooks_overwrite', False)
            invalidate_cache = request.POST.get('invalidate', False)
            log.debug('rescanning repo location with destroy obsolete=%s, '
                      'install git hooks=%s and '
                      'overwrite git hooks=%s' % (rm_obsolete, install_git_hooks, overwrite_git_hooks))

            filesystem_repos = ScmModel().repo_scan()
            added, removed = repo2db_mapper(filesystem_repos, rm_obsolete,
                                            install_git_hooks=install_git_hooks,
                                            user=request.authuser.username,
                                            overwrite_git_hooks=overwrite_git_hooks)
            added_msg = webutils.HTML(', ').join(
                webutils.link_to(safe_str(repo_name), webutils.url('summary_home', repo_name=repo_name)) for repo_name in added
            ) or '-'
            removed_msg = webutils.HTML(', ').join(
                safe_str(repo_name) for repo_name in removed
            ) or '-'
            webutils.flash(webutils.HTML(_('Repositories successfully rescanned. Added: %s. Removed: %s.')) %
                    (added_msg, removed_msg), category='success')

            if invalidate_cache:
                log.debug('invalidating all repositories cache')
                i = 0
                for repo in db.Repository.query():
                    try:
                        ScmModel().mark_for_invalidation(repo.repo_name)
                        i += 1
                    except VCSError as e:
                        log.warning('VCS error invalidating %s: %s', repo.repo_name, e)
                webutils.flash(_('Invalidated %s repositories') % i, category='success')

            raise HTTPFound(location=url('admin_settings_mapping'))

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_global(self):
        c.active = 'global'
        if request.POST:
            application_form = ApplicationSettingsForm()()
            try:
                form_result = application_form.to_python(dict(request.POST))
            except formencode.Invalid as errors:
                return htmlfill.render(
                    base.render('admin/settings/settings.html'),
                    defaults=errors.value,
                    errors=errors.error_dict or {},
                    prefix_error=False,
                    encoding="UTF-8",
                    force_defaults=False)

            try:
                for setting in (
                    'title',
                    'realm',
                    'ga_code',
                    'captcha_public_key',
                    'captcha_private_key',
                ):
                    db.Setting.create_or_update(setting, form_result[setting])

                meta.Session().commit()
                set_app_settings(config)
                webutils.flash(_('Updated application settings'), category='success')

            except Exception:
                log.error(traceback.format_exc())
                webutils.flash(_('Error occurred while updating '
                          'application settings'),
                          category='error')

            raise HTTPFound(location=url('admin_settings_global'))

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_visual(self):
        c.active = 'visual'
        if request.POST:
            application_form = ApplicationVisualisationForm()()
            try:
                form_result = application_form.to_python(dict(request.POST))
            except formencode.Invalid as errors:
                return htmlfill.render(
                    base.render('admin/settings/settings.html'),
                    defaults=errors.value,
                    errors=errors.error_dict or {},
                    prefix_error=False,
                    encoding="UTF-8",
                    force_defaults=False)

            try:
                settings = [
                    ('show_public_icon', 'show_public_icon', 'bool'),
                    ('show_private_icon', 'show_private_icon', 'bool'),
                    ('stylify_metalabels', 'stylify_metalabels', 'bool'),
                    ('repository_fields', 'repository_fields', 'bool'),
                    ('dashboard_items', 'dashboard_items', 'int'),
                    ('admin_grid_items', 'admin_grid_items', 'int'),
                    ('show_version', 'show_version', 'bool'),
                    ('use_gravatar', 'use_gravatar', 'bool'),
                    ('gravatar_url', 'gravatar_url', 'unicode'),
                    ('clone_uri_tmpl', 'clone_uri_tmpl', 'unicode'),
                    ('clone_ssh_tmpl', 'clone_ssh_tmpl', 'unicode'),
                ]
                for setting, form_key, type_ in settings:
                    db.Setting.create_or_update(setting, form_result[form_key], type_)

                meta.Session().commit()
                set_app_settings(config)
                webutils.flash(_('Updated visualisation settings'),
                        category='success')

            except Exception:
                log.error(traceback.format_exc())
                webutils.flash(_('Error occurred during updating '
                          'visualisation settings'),
                        category='error')

            raise HTTPFound(location=url('admin_settings_visual'))

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_email(self):
        c.active = 'email'
        if request.POST:
            test_email = request.POST.get('test_email')
            test_email_subj = 'Kallithea test email'
            test_body = ('Kallithea Email test, '
                               'Kallithea version: %s' % c.kallithea_version)
            if not test_email:
                webutils.flash(_('Please enter email address'), category='error')
                raise HTTPFound(location=url('admin_settings_email'))

            test_email_txt_body = EmailNotificationModel() \
                .get_email_tmpl(EmailNotificationModel.TYPE_DEFAULT,
                                'txt', body=test_body)
            test_email_html_body = EmailNotificationModel() \
                .get_email_tmpl(EmailNotificationModel.TYPE_DEFAULT,
                                'html', body=test_body)

            recipients = [test_email] if test_email else None

            notification.send_email(recipients, test_email_subj,
                             test_email_txt_body, test_email_html_body)

            webutils.flash(_('Send email task created'), category='success')
            raise HTTPFound(location=url('admin_settings_email'))

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        c.ini = kallithea.CONFIG

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_hooks(self):
        c.active = 'hooks'
        if request.POST:
            if c.visual.allow_custom_hooks_settings:
                ui_key = request.POST.get('new_hook_ui_key')
                ui_value = request.POST.get('new_hook_ui_value')

                hook_id = request.POST.get('hook_id')

                try:
                    ui_key = ui_key and ui_key.strip()
                    if ui_key in (x.ui_key for x in db.Ui.get_custom_hooks()):
                        webutils.flash(_('Hook already exists'), category='error')
                    elif ui_key and '.kallithea_' in ui_key:
                        webutils.flash(_('Hook names with ".kallithea_" are reserved for internal use. Please use another hook name.'), category='error')
                    elif ui_value and ui_key:
                        db.Ui.create_or_update_hook(ui_key, ui_value)
                        webutils.flash(_('Added new hook'), category='success')
                    elif hook_id:
                        db.Ui.delete(hook_id)
                        meta.Session().commit()

                    # check for edits
                    update = False
                    _d = request.POST.dict_of_lists()
                    for k, v, ov in zip(_d.get('hook_ui_key', []),
                                        _d.get('hook_ui_value_new', []),
                                        _d.get('hook_ui_value', [])):
                        if v != ov:
                            db.Ui.create_or_update_hook(k, v)
                            update = True

                    if update:
                        webutils.flash(_('Updated hooks'), category='success')
                    meta.Session().commit()
                except Exception:
                    log.error(traceback.format_exc())
                    webutils.flash(_('Error occurred during hook creation'),
                            category='error')

                raise HTTPFound(location=url('admin_settings_hooks'))

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        c.custom_hooks = db.Ui.get_custom_hooks()

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_search(self):
        c.active = 'search'
        if request.POST:
            repo_location = self._get_hg_ui_settings()['paths_root_path']
            full_index = request.POST.get('full_index', False)
            kallithea.lib.indexers.daemon.whoosh_index(repo_location, full_index)
            webutils.flash(_('Whoosh reindex task scheduled'), category='success')
            raise HTTPFound(location=url('admin_settings_search'))

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)

    @HasPermissionAnyDecorator('hg.admin')
    def settings_system(self):
        c.active = 'system'

        defaults = db.Setting.get_app_settings()
        defaults.update(self._get_hg_ui_settings())

        c.ini = kallithea.CONFIG
        server_info = db.Setting.get_server_info()
        for key, val in server_info.items():
            setattr(c, key, val)

        return htmlfill.render(
            base.render('admin/settings/settings.html'),
            defaults=defaults,
            encoding="UTF-8",
            force_defaults=False)
