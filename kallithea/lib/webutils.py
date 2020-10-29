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
kallithea.lib.webutils
~~~~~~~~~~~~~~~~~~~~

Helper functions that may rely on the current WSGI request, exposed in the TG2
thread-local "global" variables. It should have few dependencies so it can be
imported anywhere - just like the global variables can be used everywhere.
"""

from tg import request

import kallithea


#
# General Kallithea URL handling
#

class UrlGenerator(object):
    """Emulate pylons.url in providing a wrapper around routes.url

    This code was added during migration from Pylons to Turbogears2. Pylons
    already provided a wrapper like this, but Turbogears2 does not.

    When the routing of Kallithea is changed to use less Routes and more
    Turbogears2-style routing, this class may disappear or change.

    url() (the __call__ method) returns the URL based on a route name and
    arguments.
    url.current() returns the URL of the current page with arguments applied.

    Refer to documentation of Routes for details:
    https://routes.readthedocs.io/en/latest/generating.html#generation
    """
    def __call__(self, *args, **kwargs):
        return request.environ['routes.url'](*args, **kwargs)

    def current(self, *args, **kwargs):
        return request.environ['routes.url'].current(*args, **kwargs)


url = UrlGenerator()


def canonical_url(*args, **kargs):
    '''Like url(x, qualified=True), but returns url that not only is qualified
    but also canonical, as configured in canonical_url'''
    try:
        parts = kallithea.CONFIG.get('canonical_url', '').split('://', 1)
        kargs['host'] = parts[1]
        kargs['protocol'] = parts[0]
    except IndexError:
        kargs['qualified'] = True
    return url(*args, **kargs)


def canonical_hostname():
    '''Return canonical hostname of system'''
    try:
        parts = kallithea.CONFIG.get('canonical_url', '').split('://', 1)
        return parts[1].split('/', 1)[0]
    except IndexError:
        parts = url('home', qualified=True).split('://', 1)
        return parts[1].split('/', 1)[0]
