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
kallithea.lib.celerylib
~~~~~~~~~~~~~~~~~~~~~~~

celery libs for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Nov 27, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import logging
import os
from hashlib import sha1

from decorator import decorator
from tg import config

import kallithea
from kallithea.lib.pidlock import DaemonLock, LockHeld
from kallithea.lib.utils2 import asbool, safe_bytes
from kallithea.model import meta


log = logging.getLogger(__name__)


def task(f_org):
    """Wrapper of celery.task.task, run at import time, before kallithea.CONFIG has been set, and before kallithea.CELERY_APP has been configured.
    """

    def f_async(*args, **kwargs):
        log.info('executing async task %s', f_org.__name__)
        try:
            f_org(*args, **kwargs)
        finally:
            meta.Session.remove()  # prevent reuse of auto created db sessions
            log.info('executed async task %s', f_org.__name__)

    runner = kallithea.CELERY_APP.task(name=f_org.__name__, ignore_result=True)(f_async)

    def f_wrapped(*args, **kwargs):
        if asbool(kallithea.CONFIG.get('use_celery')):
            t = runner.apply_async(args=args, kwargs=kwargs)
            log.info('executing async task %s - id %s', f_org, t.task_id)
        else:
            # invoke f_org directly, without the meta.Session.remove in f_async
            log.info('executing sync task %s', f_org.__name__)
            try:
                f_org(*args, **kwargs)
            except Exception as e:
                log.error('exception executing sync task %s: %r', f_org.__name__, e)
                raise # TODO: report errors differently ... and consistently between sync and async

    return f_wrapped


def __get_lockkey(func, *fargs, **fkwargs):
    params = list(fargs)
    params.extend(['%s-%s' % ar for ar in fkwargs.items()])

    func_name = str(func.__name__) if hasattr(func, '__name__') else str(func)

    lockkey = 'task_%s.lock' % \
        sha1(safe_bytes(func_name + '-' + '-'.join(str(x) for x in params))).hexdigest()
    return lockkey


def locked_task(func):
    def __wrapper(func, *fargs, **fkwargs):
        lockkey = __get_lockkey(func, *fargs, **fkwargs)
        log.info('running task with lockkey %s', lockkey)
        try:
            l = DaemonLock(os.path.join(config['cache_dir'], lockkey))
            ret = func(*fargs, **fkwargs)
            l.release()
            return ret
        except LockHeld:
            log.info('LockHeld')
            return 'Task with key %s already running' % lockkey

    return decorator(__wrapper, func)
