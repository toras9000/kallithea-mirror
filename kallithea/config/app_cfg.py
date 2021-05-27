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
Global configuration file for TurboGears2 specific settings in Kallithea.

This file complements the .ini file.
"""

import logging
import os
import platform
import sys

import alembic.config
import mercurial
import tg
from alembic.migration import MigrationContext
from alembic.script.base import ScriptDirectory
from sqlalchemy import create_engine
from tg import FullStackApplicationConfigurator

import kallithea.lib.locales
import kallithea.model.base
import kallithea.model.meta
from kallithea.lib import celery_app
from kallithea.lib.utils import load_extensions, set_app_settings, set_indexer_config, set_vcs_config
from kallithea.lib.utils2 import asbool, check_git_version
from kallithea.model import db


log = logging.getLogger(__name__)


base_config = FullStackApplicationConfigurator()

base_config.update_blueprint({
    'package': kallithea,

    # Rendering Engines Configuration
    'renderers': [
        'json',
        'mako',
    ],
    'default_renderer': 'mako',
    'use_dotted_templatenames': False,

    # Configure Sessions, store data as JSON to avoid pickle security issues
    'session.enabled': True,
    'session.data_serializer': 'json',

    # Configure the base SQLALchemy Setup
    'use_sqlalchemy': True,
    'model': kallithea.model.base,
    'DBSession': kallithea.model.meta.Session,

    # Configure App without an authentication backend.
    'auth_backend': None,

    # Use custom error page for these errors. By default, Turbogears2 does not add
    # 400 in this list.
    # Explicitly listing all is considered more robust than appending to defaults,
    # in light of possible future framework changes.
    'errorpage.status_codes': [400, 401, 403, 404],

    # Disable transaction manager -- currently Kallithea takes care of transactions itself
    'tm.enabled': False,

    # Set the default i18n source language so TG doesn't search beyond 'en' in Accept-Language.
    'i18n.lang': 'en',
})

# DebugBar, a debug toolbar for TurboGears2.
# (https://github.com/TurboGears/tgext.debugbar)
# To enable it, install 'tgext.debugbar' and 'kajiki', and run Kallithea with
# 'debug = true' (not in production!)
# See the Kallithea documentation for more information.
try:
    import kajiki  # only to check its existence
    from tgext.debugbar import enable_debugbar
    assert kajiki
except ImportError:
    pass
else:
    base_config.get_blueprint_value('renderers').append('kajiki')
    enable_debugbar(base_config)


def setup_configuration(app):
    config = app.config

    if not kallithea.lib.locales.current_locale_is_valid():
        log.error("Terminating ...")
        sys.exit(1)

    # Mercurial sets encoding at module import time, so we have to monkey patch it
    hgencoding = config.get('hgencoding')
    if hgencoding:
        mercurial.encoding.encoding = hgencoding

    if config.get('ignore_alembic_revision', False):
        log.warning('database alembic revision checking is disabled')
    else:
        dbconf = config['sqlalchemy.url']
        alembic_cfg = alembic.config.Config()
        alembic_cfg.set_main_option('script_location', 'kallithea:alembic')
        alembic_cfg.set_main_option('sqlalchemy.url', dbconf)
        script_dir = ScriptDirectory.from_config(alembic_cfg)
        available_heads = sorted(script_dir.get_heads())

        engine = create_engine(dbconf)
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current_heads = sorted(str(s) for s in context.get_current_heads())
        if current_heads != available_heads:
            log.error('Failed to run Kallithea:\n\n'
                      'The database version does not match the Kallithea version.\n'
                      'Please read the documentation on how to upgrade or downgrade the database.\n'
                      'Current database version id(s): %s\n'
                      'Expected database version id(s): %s\n'
                      'If you are a developer and you know what you are doing, you can add `ignore_alembic_revision = True` '
                      'to your .ini file to skip the check.\n' % (' '.join(current_heads), ' '.join(available_heads)))
            sys.exit(1)

    # store some globals into kallithea
    kallithea.DEFAULT_USER_ID = db.User.get_default_user().user_id

    if asbool(config.get('use_celery')) and not kallithea.CELERY_APP.finalized:
        kallithea.CELERY_APP.config_from_object(celery_app.make_celery_config(config))
    kallithea.CONFIG = config

    load_extensions(root_path=config['here'])

    set_app_settings(config)

    instance_id = kallithea.CONFIG.get('instance_id', '*')
    if instance_id == '*':
        instance_id = '%s-%s' % (platform.uname()[1], os.getpid())
        kallithea.CONFIG['instance_id'] = instance_id

    # update kallithea.CONFIG with the meanwhile changed 'config'
    kallithea.CONFIG.update(config)

    # configure vcs and indexer libraries (they are supposed to be independent
    # as much as possible and thus avoid importing tg.config or
    # kallithea.CONFIG).
    set_vcs_config(kallithea.CONFIG)
    set_indexer_config(kallithea.CONFIG)

    check_git_version()

    kallithea.model.meta.Session.remove()


tg.hooks.register('configure_new_app', setup_configuration)
