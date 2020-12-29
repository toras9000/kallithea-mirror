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
kallithea.model.async_tasks
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Kallithea task modules, containing all task that suppose to be run
by celery daemon

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Oct 6, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import os
import traceback
from collections import OrderedDict
from operator import itemgetter
from time import mktime

import celery.utils.log
from tg import config

import kallithea
from kallithea.lib import celerylib, conf, ext_json
from kallithea.lib.utils2 import asbool, ascii_bytes
from kallithea.lib.vcs.utils import author_email, author_name
from kallithea.model import db, meta


__all__ = ['get_commits_stats']


log = celery.utils.log.get_task_logger(__name__)


def _author_username(author):
    """Return the username of the user identified by the email part of the 'author' string,
    default to the name or email.
    Kind of similar to h.person() ."""
    email = author_email(author)
    if email:
        user = db.User.get_by_email(email)
        if user is not None:
            return user.username
    # Still nothing?  Just pass back the author name if any, else the email
    return author_name(author) or email


@celerylib.task
def get_commits_stats(repo_name, ts_min_y, ts_max_y, recurse_limit=100):
    lockkey = celerylib.__get_lockkey('get_commits_stats', repo_name, ts_min_y,
                            ts_max_y)
    log.info('running task with lockkey %s', lockkey)
    try:
        lock = celerylib.DaemonLock(os.path.join(config['cache_dir'], lockkey))

        co_day_auth_aggr = {}
        commits_by_day_aggregate = {}
        db_repo = db.Repository.get_by_repo_name(repo_name)
        if db_repo is None:
            return

        scm_repo = db_repo.scm_instance
        repo_size = scm_repo.count()
        # return if repo have no revisions
        if repo_size < 1:
            lock.release()
            return

        skip_date_limit = True
        parse_limit = int(config.get('commit_parse_limit'))
        last_rev = None
        last_cs = None
        timegetter = itemgetter('time')

        dbrepo = db.Repository.query() \
            .filter(db.Repository.repo_name == repo_name).scalar()
        cur_stats = db.Statistics.query() \
            .filter(db.Statistics.repository == dbrepo).scalar()

        if cur_stats is not None:
            last_rev = cur_stats.stat_on_revision

        if last_rev == scm_repo.get_changeset().revision and repo_size > 1:
            # pass silently without any work if we're not on first revision or
            # current state of parsing revision(from db marker) is the
            # last revision
            lock.release()
            return

        if cur_stats:
            commits_by_day_aggregate = OrderedDict(ext_json.loads(
                                        cur_stats.commit_activity_combined))
            co_day_auth_aggr = ext_json.loads(cur_stats.commit_activity)

        log.debug('starting parsing %s', parse_limit)

        last_rev = last_rev + 1 if last_rev and last_rev >= 0 else 0
        log.debug('Getting revisions from %s to %s',
             last_rev, last_rev + parse_limit
        )
        usernames_cache = {}
        for cs in scm_repo[last_rev:last_rev + parse_limit]:
            log.debug('parsing %s', cs)
            last_cs = cs  # remember last parsed changeset
            tt = cs.date.timetuple()
            k = mktime(tt[:3] + (0, 0, 0, 0, 0, 0))

            # get username from author - similar to what h.person does
            username = usernames_cache.get(cs.author)
            if username is None:
                username = _author_username(cs.author)
                usernames_cache[cs.author] = username

            if username in co_day_auth_aggr:
                try:
                    l = [timegetter(x) for x in
                         co_day_auth_aggr[username]['data']]
                    time_pos = l.index(k)
                except ValueError:
                    time_pos = None

                if time_pos is not None and time_pos >= 0:
                    datadict = \
                        co_day_auth_aggr[username]['data'][time_pos]

                    datadict["commits"] += 1
                    datadict["added"] += len(cs.added)
                    datadict["changed"] += len(cs.changed)
                    datadict["removed"] += len(cs.removed)

                else:
                    if k >= ts_min_y and k <= ts_max_y or skip_date_limit:

                        datadict = {"time": k,
                                    "commits": 1,
                                    "added": len(cs.added),
                                    "changed": len(cs.changed),
                                    "removed": len(cs.removed),
                                   }
                        co_day_auth_aggr[username]['data'] \
                            .append(datadict)

            else:
                if k >= ts_min_y and k <= ts_max_y or skip_date_limit:
                    co_day_auth_aggr[username] = {
                                        "label": username,
                                        "data": [{"time": k,
                                                 "commits": 1,
                                                 "added": len(cs.added),
                                                 "changed": len(cs.changed),
                                                 "removed": len(cs.removed),
                                                 }],
                                        "schema": ["commits"],
                                        }

            # gather all data by day
            if k in commits_by_day_aggregate:
                commits_by_day_aggregate[k] += 1
            else:
                commits_by_day_aggregate[k] = 1

        overview_data = sorted(commits_by_day_aggregate.items(),
                               key=itemgetter(0))

        stats = cur_stats if cur_stats else db.Statistics()
        stats.commit_activity = ascii_bytes(ext_json.dumps(co_day_auth_aggr))
        stats.commit_activity_combined = ascii_bytes(ext_json.dumps(overview_data))

        log.debug('last revision %s', last_rev)
        leftovers = len(scm_repo.revisions[last_rev:])
        log.debug('revisions to parse %s', leftovers)

        if last_rev == 0 or leftovers < parse_limit:
            log.debug('getting code trending stats')
            stats.languages = ascii_bytes(ext_json.dumps(__get_codes_stats(repo_name)))

        try:
            stats.repository = dbrepo
            stats.stat_on_revision = last_cs.revision if last_cs else 0
            meta.Session().add(stats)
            meta.Session().commit()
        except:
            log.error(traceback.format_exc())
            meta.Session().rollback()
            lock.release()
            return

        # final release
        lock.release()

        # execute another task if celery is enabled
        if len(scm_repo.revisions) > 1 and asbool(kallithea.CONFIG.get('use_celery')) and recurse_limit > 0:
            get_commits_stats(repo_name, ts_min_y, ts_max_y, recurse_limit - 1)
        elif recurse_limit <= 0:
            log.debug('Not recursing - limit has been reached')
        else:
            log.debug('Not recursing')
    except celerylib.LockHeld:
        log.info('Task with key %s already running', lockkey)


def __get_codes_stats(repo_name):
    scm_repo = db.Repository.get_by_repo_name(repo_name).scm_instance

    tip = scm_repo.get_changeset()
    code_stats = {}

    for _topnode, _dirnodes, filenodes in tip.walk('/'):
        for filenode in filenodes:
            ext = filenode.extension.lower()
            if ext in conf.LANGUAGES_EXTENSIONS_MAP and not filenode.is_binary:
                if ext in code_stats:
                    code_stats[ext] += 1
                else:
                    code_stats[ext] = 1

    return code_stats or {}
