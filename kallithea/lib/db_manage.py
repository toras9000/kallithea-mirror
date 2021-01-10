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
kallithea.lib.db_manage
~~~~~~~~~~~~~~~~~~~~~~~

Database creation, and setup module for Kallithea. Used for creation
of database as well as for migration operations

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 10, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import getpass
import logging
import os
import sys
import uuid

import alembic.command
import alembic.config
import sqlalchemy
from sqlalchemy.engine import create_engine

from kallithea.lib.utils2 import ask_ok
from kallithea.model import db, meta
from kallithea.model.base import init_model
from kallithea.model.permission import PermissionModel
from kallithea.model.user import UserModel


log = logging.getLogger(__name__)


class DbManage(object):
    def __init__(self, dbconf, root, SESSION=None, cli_args=None):
        self.dbname = dbconf.split('/')[-1]
        self.root = root
        self.dburi = dbconf
        self.cli_args = cli_args or {}
        self.init_db(SESSION=SESSION)

    def _ask_ok(self, msg):
        """Invoke ask_ok unless the force_ask option provides the answer"""
        force_ask = self.cli_args.get('force_ask')
        if force_ask is not None:
            return force_ask
        return ask_ok(msg)

    def init_db(self, SESSION=None):
        if SESSION:
            self.sa = SESSION
        else:
            # init new sessions
            engine = create_engine(self.dburi)
            init_model(engine)
            self.sa = meta.Session()

    def create_tables(self, reuse_database=False):
        """
        Create database (optional) and tables.
        If reuse_database is false, the database will be dropped (if it exists)
        and a new one created. If true, the existing database will be reused
        and cleaned for content.
        """
        url = sqlalchemy.engine.url.make_url(self.dburi)
        database = url.database
        if reuse_database:
            log.info("The content of the database %r will be destroyed and new tables created." % database)
        else:
            log.info("The existing database %r will be destroyed and a new one created." % database)

        if not self._ask_ok('Are you sure to destroy old database? [y/n]'):
            print('Nothing done.')
            sys.exit(0)

        if reuse_database:
            meta.Base.metadata.drop_all()
        else:
            if url.drivername == 'mysql':
                url.database = None  # don't connect to the database (it might not exist)
                engine = sqlalchemy.create_engine(url)
                with engine.connect() as conn:
                    conn.execute('DROP DATABASE IF EXISTS `%s`' % database)
                    conn.execute('CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci' % database)
            elif url.drivername == 'postgresql':
                from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
                url.database = 'postgres'  # connect to the system database (as the real one might not exist)
                engine = sqlalchemy.create_engine(url)
                with engine.connect() as conn:
                    conn.connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                    conn.execute('DROP DATABASE IF EXISTS "%s"' % database)
                    conn.execute('CREATE DATABASE "%s"' % database)
            else:
                # Some databases enforce foreign key constraints and Base.metadata.drop_all() doesn't work, but this is
                # known to work on SQLite - possibly not on other databases with strong referential integrity
                meta.Base.metadata.drop_all()

        meta.Base.metadata.create_all(checkfirst=False)

        # Create an Alembic configuration and generate the version table,
        # "stamping" it with the most recent Alembic migration revision, to
        # tell Alembic that all the schema upgrades are already in effect.
        alembic_cfg = alembic.config.Config()
        alembic_cfg.set_main_option('script_location', 'kallithea:alembic')
        alembic_cfg.set_main_option('sqlalchemy.url', self.dburi)
        # This command will give an error in an Alembic multi-head scenario,
        # but in practice, such a scenario should not come up during database
        # creation, even during development.
        alembic.command.stamp(alembic_cfg, 'head')

        log.info('Created tables for %s', self.dbname)

    def create_admin_user(self):
        username = self.cli_args.get('username')
        password = self.cli_args.get('password')
        email = self.cli_args.get('email')

        def get_password():
            password = getpass.getpass('Specify admin password '
                                       '(min 6 chars):')
            confirm = getpass.getpass('Confirm password:')

            if password != confirm:
                log.error('passwords mismatch')
                return False
            if len(password) < 6:
                log.error('password is to short use at least 6 characters')
                return False

            return password
        if username is None:
            username = input('Specify admin username:')
        if password is None:
            password = get_password()
            if not password:
                # second try
                password = get_password()
                if not password:
                    sys.exit()
        if email is None:
            email = input('Specify admin email:')
        self.create_user(username, password, email, True)

    def create_auth_plugin_options(self, skip_existing=False):
        """
        Create default auth plugin settings, and make it active

        :param skip_existing:
        """

        for k, v, t in [('auth_plugins', 'kallithea.lib.auth_modules.auth_internal', 'list'),
                        ('auth_internal_enabled', 'True', 'bool')]:
            if skip_existing and db.Setting.get_by_name(k) is not None:
                log.debug('Skipping option %s', k)
                continue
            setting = db.Setting(k, v, t)
            self.sa.add(setting)

    def create_default_options(self, skip_existing=False):
        """Creates default settings"""

        for k, v, t in [
            ('default_repo_enable_downloads', False, 'bool'),
            ('default_repo_enable_statistics', False, 'bool'),
            ('default_repo_private', False, 'bool'),
            ('default_repo_type', 'hg', 'unicode')
        ]:
            if skip_existing and db.Setting.get_by_name(k) is not None:
                log.debug('Skipping option %s', k)
                continue
            setting = db.Setting(k, v, t)
            self.sa.add(setting)

    def prompt_repo_root_path(self, test_repo_path='', retries=3):
        _path = self.cli_args.get('repos_location')
        if retries == 3:
            log.info('Setting up repositories config')

        if _path is not None:
            path = _path
        elif not test_repo_path:
            path = input(
                 'Enter a valid absolute path to store repositories. '
                 'All repositories in that path will be added automatically:'
            )
        else:
            path = test_repo_path
        path_ok = True

        # check proper dir
        if not os.path.isdir(path):
            path_ok = False
            log.error('Given path %s is not a valid directory', path)

        elif not os.path.isabs(path):
            path_ok = False
            log.error('Given path %s is not an absolute path', path)

        # check if path is at least readable.
        if not os.access(path, os.R_OK):
            path_ok = False
            log.error('Given path %s is not readable', path)

        # check write access, warn user about non writeable paths
        elif not os.access(path, os.W_OK) and path_ok:
            log.warning('No write permission to given path %s', path)
            if not self._ask_ok('Given path %s is not writeable, do you want to '
                          'continue with read only mode ? [y/n]' % (path,)):
                log.error('Canceled by user')
                sys.exit(-1)

        if retries == 0:
            sys.exit('max retries reached')
        if not path_ok:
            if _path is not None:
                sys.exit('Invalid repo path: %s' % _path)
            retries -= 1
            return self.prompt_repo_root_path(test_repo_path, retries) # recursing!!!

        real_path = os.path.normpath(os.path.realpath(path))

        if real_path != os.path.normpath(path):
            log.warning('Using normalized path %s instead of %s', real_path, path)

        return real_path

    def create_settings(self, repo_root_path):
        ui_config = [
            ('paths', '/', repo_root_path, True),
            #('phases', 'publish', 'false', False)
            ('hooks', db.Ui.HOOK_UPDATE, 'python:', False),  # the actual value in db doesn't matter
            ('hooks', db.Ui.HOOK_REPO_SIZE, 'python:', True),  # the actual value in db doesn't matter
            ('extensions', 'largefiles', '', True),
            ('largefiles', 'usercache', os.path.join(repo_root_path, '.cache', 'largefiles'), True),
            ('extensions', 'hggit', '', False),
        ]
        for ui_section, ui_key, ui_value, ui_active in ui_config:
            ui_conf = db.Ui(
                ui_section=ui_section,
                ui_key=ui_key,
                ui_value=ui_value,
                ui_active=ui_active)
            self.sa.add(ui_conf)

        settings = [
            ('realm', 'Kallithea', 'unicode'),
            ('title', '', 'unicode'),
            ('ga_code', '', 'unicode'),
            ('show_public_icon', True, 'bool'),
            ('show_private_icon', True, 'bool'),
            ('stylify_metalabels', False, 'bool'),
            ('dashboard_items', 100, 'int'), # TODO: call it page_size
            ('admin_grid_items', 25, 'int'),
            ('show_version', True, 'bool'),
            ('use_gravatar', True, 'bool'),
            ('gravatar_url', db.User.DEFAULT_GRAVATAR_URL, 'unicode'),
            ('clone_uri_tmpl', db.Repository.DEFAULT_CLONE_URI, 'unicode'),
            ('clone_ssh_tmpl', db.Repository.DEFAULT_CLONE_SSH, 'unicode'),
        ]
        for key, val, type_ in settings:
            sett = db.Setting(key, val, type_)
            self.sa.add(sett)

        self.create_auth_plugin_options()
        self.create_default_options()

        log.info('Populated Ui and Settings defaults')

    def create_user(self, username, password, email='', admin=False):
        log.info('creating user %s', username)
        UserModel().create_or_update(username, password, email,
                                     firstname='Kallithea', lastname='Admin',
                                     active=True, admin=admin,
                                     extern_type=db.User.DEFAULT_AUTH_TYPE)

    def create_default_user(self):
        log.info('creating default user')
        # create default user for handling default permissions.
        user = UserModel().create_or_update(username=db.User.DEFAULT_USER_NAME,
                                            password=str(uuid.uuid1())[:20],
                                            email='anonymous@kallithea-scm.org',
                                            firstname='Anonymous',
                                            lastname='User')
        # based on configuration options activate/deactivate this user which
        # controls anonymous access
        if self.cli_args.get('public_access') is False:
            log.info('Public access disabled')
            user.active = False
            meta.Session().commit()

    def create_permissions(self):
        """
        Creates all permissions defined in the system
        """
        # module.(access|create|change|delete)_[name]
        # module.(none|read|write|admin)
        log.info('creating permissions')
        PermissionModel().create_permissions()

    def populate_default_permissions(self):
        """
        Populate default permissions. It will create only the default
        permissions that are missing, and not alter already defined ones
        """
        log.info('creating default user permissions')
        PermissionModel().create_default_permissions(user=db.User.DEFAULT_USER_NAME)
