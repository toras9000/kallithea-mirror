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
kallithea.model.userlog
~~~~~~~~~~~~~~~~~~~~~~~

Database Models for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 08, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""


import datetime
import logging

from kallithea.lib.utils2 import get_current_authuser
from kallithea.model import db, meta


log = logging.getLogger(__name__)


def action_logger(user, action, repo, ipaddr='', commit=False):
    """
    Action logger for various actions made by users

    :param user: user that made this action, can be a unique username string or
        object containing user_id attribute
    :param action: action to log, should be on of predefined unique actions for
        easy translations
    :param repo: string name of repository or object containing repo_id,
        that action was made on
    :param ipaddr: optional IP address from what the action was made

    """

    # if we don't get explicit IP address try to get one from registered user
    # in tmpl context var
    if not ipaddr:
        ipaddr = getattr(get_current_authuser(), 'ip_addr', '')

    if getattr(user, 'user_id', None):
        user_obj = db.User.get(user.user_id)
    elif isinstance(user, str):
        user_obj = db.User.get_by_username(user)
    else:
        raise Exception('You have to provide a user object or a username')

    if getattr(repo, 'repo_id', None):
        repo_obj = db.Repository.get(repo.repo_id)
        repo_name = repo_obj.repo_name
    elif isinstance(repo, str):
        repo_name = repo.lstrip('/')
        repo_obj = db.Repository.get_by_repo_name(repo_name)
    else:
        repo_obj = None
        repo_name = ''

    user_log = db.UserLog()
    user_log.user_id = user_obj.user_id
    user_log.username = user_obj.username
    user_log.action = action

    user_log.repository = repo_obj
    user_log.repository_name = repo_name

    user_log.action_date = datetime.datetime.now()
    user_log.user_ip = ipaddr
    meta.Session().add(user_log)

    log.info('Logging action:%s on %s by user:%s ip:%s',
             action, repo, user_obj, ipaddr)
    if commit:
        meta.Session().commit()
