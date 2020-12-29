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

import email.message
import email.utils
import os
import smtplib
import time
import traceback
from collections import OrderedDict
from operator import itemgetter
from time import mktime

import celery.utils.log
from tg import config

import kallithea
from kallithea.lib import celerylib, conf, ext_json, hooks
from kallithea.lib.utils2 import asbool, ascii_bytes
from kallithea.lib.vcs.utils import author_email, author_name
from kallithea.model import db, meta, repo, userlog


__all__ = ['get_commits_stats', 'send_email']


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


@celerylib.task
def send_email(recipients, subject, body='', html_body='', headers=None, from_name=None):
    """
    Sends an email with defined parameters from the .ini files.

    :param recipients: list of recipients, if this is None, the defined email
        address from field 'email_to' and all admins is used instead
    :param subject: subject of the mail
    :param body: plain text body of the mail
    :param html_body: html version of body
    :param headers: dictionary of prepopulated e-mail headers
    :param from_name: full name to be used as sender of this mail - often a
    .full_name_or_username value
    """
    assert isinstance(recipients, list), recipients
    if headers is None:
        headers = {}
    else:
        # do not modify the original headers object passed by the caller
        headers = headers.copy()

    email_config = config
    email_prefix = email_config.get('email_prefix', '')
    if email_prefix:
        subject = "%s %s" % (email_prefix, subject)

    if not recipients:
        # if recipients are not defined we send to email_config + all admins
        recipients = [u.email for u in db.User.query()
                      .filter(db.User.admin == True).all()]
        if email_config.get('email_to') is not None:
            recipients += email_config.get('email_to').split(',')

        # If there are still no recipients, there are no admins and no address
        # configured in email_to, so return.
        if not recipients:
            log.error("No recipients specified and no fallback available.")
            return

        log.warning("No recipients specified for '%s' - sending to admins %s", subject, ' '.join(recipients))

    # SMTP sender
    app_email_from = email_config.get('app_email_from', 'Kallithea')
    # 'From' header
    if from_name is not None:
        # set From header based on from_name but with a generic e-mail address
        # In case app_email_from is in "Some Name <e-mail>" format, we first
        # extract the e-mail address.
        envelope_addr = author_email(app_email_from)
        headers['From'] = '"%s" <%s>' % (
            email.utils.quote('%s (no-reply)' % from_name),
            envelope_addr)

    smtp_server = email_config.get('smtp_server')
    smtp_port = email_config.get('smtp_port')
    smtp_use_tls = asbool(email_config.get('smtp_use_tls'))
    smtp_use_ssl = asbool(email_config.get('smtp_use_ssl'))
    smtp_auth = email_config.get('smtp_auth')  # undocumented - overrule automatic choice of auth mechanism
    smtp_username = email_config.get('smtp_username')
    smtp_password = email_config.get('smtp_password')

    logmsg = ("Mail details:\n"
              "recipients: %s\n"
              "headers: %s\n"
              "subject: %s\n"
              "body:\n%s\n"
              "html:\n%s\n"
              % (' '.join(recipients), headers, subject, body, html_body))

    if smtp_server:
        log.debug("Sending e-mail. " + logmsg)
    else:
        log.error("SMTP mail server not configured - cannot send e-mail.")
        log.warning(logmsg)
        return

    msg = email.message.EmailMessage()
    msg['Subject'] = subject
    msg['From'] = app_email_from  # fallback - might be overridden by a header
    msg['To'] = ', '.join(recipients)
    msg['Date'] = email.utils.formatdate(time.time())

    for key, value in headers.items():
        del msg[key]  # Delete key first to make sure add_header will replace header (if any), no matter the casing
        msg.add_header(key, value)

    msg.set_content(body)
    msg.add_alternative(html_body, subtype='html')

    try:
        if smtp_use_ssl:
            smtp_serv = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            smtp_serv = smtplib.SMTP(smtp_server, smtp_port)

        if smtp_use_tls:
            smtp_serv.starttls()

        if smtp_auth:
            smtp_serv.ehlo()  # populate esmtp_features
            smtp_serv.esmtp_features["auth"] = smtp_auth

        if smtp_username and smtp_password is not None:
            smtp_serv.login(smtp_username, smtp_password)

        smtp_serv.sendmail(app_email_from, recipients, msg.as_string())
        smtp_serv.quit()

        log.info('Mail was sent to: %s' % recipients)
    except:
        log.error('Mail sending failed')
        log.error(traceback.format_exc())


@celerylib.task
def create_repo(form_data, cur_user):
    cur_user = db.User.guess_instance(cur_user)

    owner = cur_user
    repo_name = form_data['repo_name']
    repo_name_full = form_data['repo_name_full']
    repo_type = form_data['repo_type']
    description = form_data['repo_description']
    private = form_data['repo_private']
    clone_uri = form_data.get('clone_uri')
    repo_group = form_data['repo_group']
    landing_rev = form_data['repo_landing_rev']
    copy_fork_permissions = form_data.get('copy_permissions')
    copy_group_permissions = form_data.get('repo_copy_permissions')
    fork_of = form_data.get('fork_parent_id')
    state = form_data.get('repo_state', db.Repository.STATE_PENDING)

    # repo creation defaults, private and repo_type are filled in form
    defs = db.Setting.get_default_repo_settings(strip_prefix=True)
    enable_statistics = defs.get('repo_enable_statistics')
    enable_downloads = defs.get('repo_enable_downloads')

    try:
        db_repo = repo.RepoModel()._create_repo(
            repo_name=repo_name_full,
            repo_type=repo_type,
            description=description,
            owner=owner,
            private=private,
            clone_uri=clone_uri,
            repo_group=repo_group,
            landing_rev=landing_rev,
            fork_of=fork_of,
            copy_fork_permissions=copy_fork_permissions,
            copy_group_permissions=copy_group_permissions,
            enable_statistics=enable_statistics,
            enable_downloads=enable_downloads,
            state=state
        )

        userlog.action_logger(cur_user, 'user_created_repo',
                      form_data['repo_name_full'], '')

        meta.Session().commit()
        # now create this repo on Filesystem
        repo.RepoModel()._create_filesystem_repo(
            repo_name=repo_name,
            repo_type=repo_type,
            repo_group=db.RepoGroup.guess_instance(repo_group),
            clone_uri=clone_uri,
        )
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        hooks.log_create_repository(db_repo.get_dict(), created_by=owner.username)

        # update repo changeset caches initially
        db_repo.update_changeset_cache()

        # set new created state
        db_repo.set_state(db.Repository.STATE_CREATED)
        meta.Session().commit()
    except Exception as e:
        log.warning('Exception %s occurred when forking repository, '
                    'doing cleanup...' % e)
        # rollback things manually !
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        if db_repo:
            db.Repository.delete(db_repo.repo_id)
            meta.Session().commit()
            repo.RepoModel()._delete_filesystem_repo(db_repo)
        raise


@celerylib.task
def create_repo_fork(form_data, cur_user):
    """
    Creates a fork of repository using interval VCS methods

    :param form_data:
    :param cur_user:
    """
    base_path = kallithea.CONFIG['base_path']
    cur_user = db.User.guess_instance(cur_user)

    repo_name = form_data['repo_name']  # fork in this case
    repo_name_full = form_data['repo_name_full']

    repo_type = form_data['repo_type']
    owner = cur_user
    private = form_data['private']
    clone_uri = form_data.get('clone_uri')
    repo_group = form_data['repo_group']
    landing_rev = form_data['landing_rev']
    copy_fork_permissions = form_data.get('copy_permissions')

    try:
        fork_of = db.Repository.guess_instance(form_data.get('fork_parent_id'))

        repo.RepoModel()._create_repo(
            repo_name=repo_name_full,
            repo_type=repo_type,
            description=form_data['description'],
            owner=owner,
            private=private,
            clone_uri=clone_uri,
            repo_group=repo_group,
            landing_rev=landing_rev,
            fork_of=fork_of,
            copy_fork_permissions=copy_fork_permissions
        )
        userlog.action_logger(cur_user, 'user_forked_repo:%s' % repo_name_full,
                      fork_of.repo_name, '')
        meta.Session().commit()

        source_repo_path = os.path.join(base_path, fork_of.repo_name)

        # now create this repo on Filesystem
        repo.RepoModel()._create_filesystem_repo(
            repo_name=repo_name,
            repo_type=repo_type,
            repo_group=db.RepoGroup.guess_instance(repo_group),
            clone_uri=source_repo_path,
        )
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        hooks.log_create_repository(db_repo.get_dict(), created_by=owner.username)

        # update repo changeset caches initially
        db_repo.update_changeset_cache()

        # set new created state
        db_repo.set_state(db.Repository.STATE_CREATED)
        meta.Session().commit()
    except Exception as e:
        log.warning('Exception %s occurred when forking repository, '
                    'doing cleanup...' % e)
        # rollback things manually !
        db_repo = db.Repository.get_by_repo_name(repo_name_full)
        if db_repo:
            db.Repository.delete(db_repo.repo_id)
            meta.Session().commit()
            repo.RepoModel()._delete_filesystem_repo(db_repo)
        raise


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
