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
kallithea.model.api_key
~~~~~~~~~~~~~~~~~~~~~~~

API key model for Kallithea

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Sep 8, 2013
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
import time

from kallithea.lib.utils2 import generate_api_key
from kallithea.model import db, meta


log = logging.getLogger(__name__)


class ApiKeyModel(object):

    def create(self, user, description, lifetime=-1):
        """
        :param user: user or user_id
        :param description: description of ApiKey
        :param lifetime: expiration time in seconds
        """
        user = db.User.guess_instance(user)

        new_api_key = db.UserApiKeys()
        new_api_key.api_key = generate_api_key()
        new_api_key.user_id = user.user_id
        new_api_key.description = description
        new_api_key.expires = time.time() + (lifetime * 60) if lifetime != -1 else -1
        meta.Session().add(new_api_key)

        return new_api_key

    def delete(self, api_key, user=None):
        """
        Deletes given api_key, if user is set it also filters the object for
        deletion by given user.
        """
        api_key = db.UserApiKeys.query().filter(db.UserApiKeys.api_key == api_key)

        if user is not None:
            user = db.User.guess_instance(user)
            api_key = api_key.filter(db.UserApiKeys.user_id == user.user_id)

        api_key = api_key.scalar()
        meta.Session().delete(api_key)

    def get_api_keys(self, user, show_expired=True):
        user = db.User.guess_instance(user)
        user_api_keys = db.UserApiKeys.query() \
            .filter(db.UserApiKeys.user_id == user.user_id)
        if not show_expired:
            user_api_keys = user_api_keys.filter_by(is_expired=False)
        return user_api_keys
