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
kallithea.tests.scripts.manual_test_concurrency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test suite for making push/pull operations

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Dec 30, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.

"""

import logging
import os
import shutil
import sys
import tempfile
from os.path import dirname
from subprocess import PIPE, Popen

from paste.deploy import appconfig
from sqlalchemy import engine_from_config

import kallithea.config.application
from kallithea.lib.utils2 import get_crypt_password
from kallithea.model import db, meta
from kallithea.model.base import init_model
from kallithea.model.repo import RepoModel
from kallithea.tests.base import HG_REPO, TEST_USER_ADMIN_LOGIN, TEST_USER_ADMIN_PASS


rel_path = dirname(dirname(dirname(dirname(os.path.abspath(__file__)))))
conf = appconfig('config:development.ini', relative_to=rel_path)
kallithea.config.application.make_app(conf.global_conf, **conf.local_conf)

USER = TEST_USER_ADMIN_LOGIN
PASS = TEST_USER_ADMIN_PASS
HOST = 'server.local'
METHOD = 'pull'
DEBUG = True
log = logging.getLogger(__name__)


class Command(object):

    def __init__(self, cwd):
        self.cwd = cwd

    def execute(self, cmd, *args):
        """Runs command on the system with given ``args``.
        """

        command = cmd + ' ' + ' '.join(args)
        log.debug('Executing %s', command)
        if DEBUG:
            print(command)
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE, cwd=self.cwd)
        stdout, stderr = p.communicate()
        if DEBUG:
            print(stdout, stderr)
        return stdout, stderr


def get_session():
    engine = engine_from_config(conf, 'sqlalchemy.')
    init_model(engine)
    sa = meta.Session
    return sa


def create_test_user(force=True):
    print('creating test user')
    sa = get_session()

    user = sa.query(db.User).filter(db.User.username == USER).scalar()

    if force and user is not None:
        print('removing current user')
        for repo in sa.query(db.Repository).filter(db.Repository.user == user).all():
            sa.delete(repo)
        sa.delete(user)
        sa.commit()

    if user is None or force:
        print('creating new one')
        new_usr = db.User()
        new_usr.username = USER
        new_usr.password = get_crypt_password(PASS)
        new_usr.email = 'mail@example.com'
        new_usr.name = 'test'
        new_usr.lastname = 'lasttestname'
        new_usr.active = True
        new_usr.admin = True
        sa.add(new_usr)
        sa.commit()

    print('done')


def create_test_repo(force=True):
    print('creating test repo')
    sa = get_session()

    user = sa.query(db.User).filter(db.User.username == USER).scalar()
    if user is None:
        raise Exception('user not found')

    repo = sa.query(db.Repository).filter(db.Repository.repo_name == HG_REPO).scalar()

    if repo is None:
        print('repo not found creating')

        form_data = {'repo_name': HG_REPO,
                     'repo_type': 'hg',
                     'private': False,
                     'clone_uri': ''}
        rm = RepoModel()
        rm.base_path = '/home/hg'
        rm.create(form_data, user)

    print('done')


def set_anonymous_access(enable=True):
    sa = get_session()
    user = sa.query(db.User).filter(db.User.username == 'default').one()
    user.active = enable
    sa.add(user)
    sa.commit()


def get_anonymous_access():
    sa = get_session()
    return sa.query(db.User).filter(db.User.username == 'default').one().active


#==============================================================================
# TESTS
#==============================================================================
def test_clone_with_credentials(no_errors=False, repo=HG_REPO, method=METHOD,
                                backend='hg'):
    cwd = path = os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo)

    try:
        shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path)
        #print 'made dirs %s' % os.path.join(path)
    except OSError:
        raise

    clone_url = 'http://%(user)s:%(pass)s@%(host)s/%(cloned_repo)s' % \
                  {'user': USER,
                   'pass': PASS,
                   'host': HOST,
                   'cloned_repo': repo, }

    dest = tempfile.mktemp(dir=path, prefix='dest-')
    if method == 'pull':
        stdout, stderr = Command(cwd).execute(backend, method, '--cwd', dest, clone_url)
    else:
        stdout, stderr = Command(cwd).execute(backend, method, clone_url, dest)
        if not no_errors:
            if backend == 'hg':
                assert """adding file changes""" in stdout, 'no messages about cloning'
                assert """abort""" not in stderr, 'got error from clone'
            elif backend == 'git':
                assert """Cloning into""" in stdout, 'no messages about cloning'


if __name__ == '__main__':
    try:
        create_test_user(force=False)
        import time

        try:
            METHOD = sys.argv[3]
        except IndexError:
            pass

        try:
            backend = sys.argv[4]
        except IndexError:
            backend = 'hg'

        if METHOD == 'pull':
            seq = next(tempfile._RandomNameSequence())  # pytype: disable=module-attr
            test_clone_with_credentials(repo=sys.argv[1], method='clone',
                                        backend=backend)
        s = time.time()
        for i in range(1, int(sys.argv[2]) + 1):
            print('take', i)
            test_clone_with_credentials(repo=sys.argv[1], method=METHOD,
                                        backend=backend)
        print('time taken %.3f' % (time.time() - s))
    except Exception as e:
        sys.exit('stop on %s' % e)
