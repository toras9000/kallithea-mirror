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
kallithea
~~~~~~~~~

Kallithea, a web based repository management system.

Versioning implementation: http://www.python.org/dev/peps/pep-0386/

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Apr 9, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, (C) 2014 Bradley M. Kuhn, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import platform
import sys

import celery


if sys.version_info < (3, 6):
    raise Exception('Kallithea requires python 3.6 or later')

VERSION = (0, 7, 99)
BACKENDS = {
    'hg': 'Mercurial repository',
    'git': 'Git repository',
}

CELERY_APP = celery.Celery()  # needed at import time but is lazy and can be configured later

DEFAULT_USER_ID: int  # set by setup_configuration
CONFIG = {}  # set to tg.config when TG app is initialized and calls app_cfg

# URL prefix for non repository related links - must start with `/`
ADMIN_PREFIX = '/_admin'
URL_SEP = '/'

# Linked module for extensions
EXTENSIONS = {}

__version__ = '.'.join(str(each) for each in VERSION)
__platform__ = platform.system()
__license__ = 'GPLv3'
__py_version__ = sys.version_info
__author__ = "Various Authors"
__url__ = 'https://kallithea-scm.org/'

is_windows = __platform__ in ['Windows']
is_unix = not is_windows
