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
kallithea.bin.base
~~~~~~~~~~~~~~~~~~

Base utils for shell scripts

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: May 09, 2013
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import os
import pprint
import random
import sys
import urllib.request

from kallithea.lib import ext_json
from kallithea.lib.utils2 import ascii_bytes


CONFIG_NAME = '.config/kallithea'
FORMAT_PRETTY = 'pretty'
FORMAT_JSON = 'json'


def api_call(apikey, apihost, method=None, **kw):
    """
    Api_call wrapper for Kallithea.

    :param apikey:
    :param apihost:
    :param format: formatting, pretty means prints and pprint of json
     json returns unparsed json
    :param method:
    :returns: json response from server
    """
    def _build_data(random_id):
        """
        Builds API data with given random ID

        :param random_id:
        """
        return {
            "id": random_id,
            "api_key": apikey,
            "method": method,
            "args": kw
        }

    if not method:
        raise Exception('please specify method name !')
    apihost = apihost.rstrip('/')
    id_ = random.randrange(1, 9999)
    req = urllib.request.Request('%s/_admin/api' % apihost,
                      data=ascii_bytes(ext_json.dumps(_build_data(id_))),
                      headers={'content-type': 'text/plain'})
    ret = urllib.request.urlopen(req)
    raw_json = ret.read()
    json_data = ext_json.loads(raw_json)
    id_ret = json_data['id']
    if id_ret == id_:
        return json_data

    else:
        _formatted_json = pprint.pformat(json_data)
        raise Exception('something went wrong. '
                        'ID mismatch got %s, expected %s | %s' % (
                                            id_ret, id_, _formatted_json))


class RcConf(object):
    """
    Kallithea config for API

    conf = RcConf()
    conf['key']

    """

    def __init__(self, config_location=None, autoload=True, autocreate=False,
                 config=None):
        HOME = os.getenv('HOME', os.getenv('USERPROFILE')) or ''
        HOME_CONF = os.path.abspath(os.path.join(HOME, CONFIG_NAME))
        self._conf_name = HOME_CONF if not config_location else config_location
        self._conf = {}
        if autocreate:
            self.make_config(config)
        if autoload:
            self._conf = self.load_config()

    def __getitem__(self, key):
        return self._conf[key]

    def __bool__(self):
        if self._conf:
            return True
        return False

    def __eq__(self, other):
        return self._conf.__eq__(other)

    def __repr__(self):
        return 'RcConf<%s>' % self._conf.__repr__()

    def make_config(self, config):
        """
        Saves given config as a JSON dump in the _conf_name location

        :param config:
        """
        update = False
        if os.path.exists(self._conf_name):
            update = True
        with open(self._conf_name, 'w') as f:
            ext_json.dump(config, f, indent=4)
            f.write('\n')

        if update:
            sys.stdout.write('Updated config in %s\n' % self._conf_name)
        else:
            sys.stdout.write('Created new config in %s\n' % self._conf_name)

    def load_config(self):
        """
        Loads config from file and returns loaded JSON object
        """
        try:
            with open(self._conf_name, 'r') as conf:
                return ext_json.load(conf)
        except IOError as e:
            #sys.stderr.write(str(e) + '\n')
            pass
