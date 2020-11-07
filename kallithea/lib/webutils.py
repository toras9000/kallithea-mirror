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
~~~~~~~~~~~~~~~~~~~~~~

Helper functions that may rely on the current WSGI request, exposed in the TG2
thread-local "global" variables. It should have few dependencies so it can be
imported anywhere - just like the global variables can be used everywhere.
"""

import json
import logging
import random

from tg import request, session
from webhelpers2.html import HTML, escape, literal
from webhelpers2.html.tags import NotGiven, Option, Options, _input
from webhelpers2.html.tags import _make_safe_id_component as safeid
from webhelpers2.html.tags import checkbox, end_form
from webhelpers2.html.tags import form as insecure_form
from webhelpers2.html.tags import hidden, link_to, password, radio
from webhelpers2.html.tags import select as webhelpers2_select
from webhelpers2.html.tags import submit, text, textarea
from webhelpers2.number import format_byte_size
from webhelpers2.text import chop_at, truncate, wrap_paragraphs

import kallithea


log = logging.getLogger(__name__)


# mute pyflakes "imported but unused"
assert Option
assert checkbox
assert chop_at
assert end_form
assert escape
assert format_byte_size
assert link_to
assert literal
assert password
assert radio
assert safeid
assert submit
assert text
assert textarea
assert truncate
assert wrap_paragraphs


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


#
# Custom Webhelpers2 stuff
#

def html_escape(s):
    """Return string with all html escaped.
    This is also safe for javascript in html but not necessarily correct.
    """
    return (s
        .replace('&', '&amp;')
        .replace(">", "&gt;")
        .replace("<", "&lt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;") # Note: this is HTML5 not HTML4 and might not work in mails
        )


def reset(name, value, id=NotGiven, **attrs):
    """Create a reset button, similar to webhelpers2.html.tags.submit ."""
    return _input("reset", name, value, id, attrs)


def select(name, selected_values, options, id=NotGiven, **attrs):
    """Convenient wrapper of webhelpers2 to let it accept options as a tuple list"""
    if isinstance(options, list):
        option_list = options
        # Handle old value,label lists ... where value also can be value,label lists
        options = Options()
        for x in option_list:
            if isinstance(x, tuple) and len(x) == 2:
                value, label = x
            elif isinstance(x, str):
                value = label = x
            else:
                log.error('invalid select option %r', x)
                raise
            if isinstance(value, list):
                og = options.add_optgroup(label)
                for x in value:
                    if isinstance(x, tuple) and len(x) == 2:
                        group_value, group_label = x
                    elif isinstance(x, str):
                        group_value = group_label = x
                    else:
                        log.error('invalid select option %r', x)
                        raise
                    og.add_option(group_label, group_value)
            else:
                options.add_option(label, value)
    return webhelpers2_select(name, selected_values, options, id=id, **attrs)


session_csrf_secret_name = "_session_csrf_secret_token"

def session_csrf_secret_token():
    """Return (and create) the current session's CSRF protection token."""
    if not session_csrf_secret_name in session:
        session[session_csrf_secret_name] = str(random.getrandbits(128))
        session.save()
    return session[session_csrf_secret_name]

def form(url, method="post", **attrs):
    """Like webhelpers.html.tags.form , but automatically adding
    session_csrf_secret_token for POST. The secret is thus never leaked in GET
    URLs.
    """
    form = insecure_form(url, method, **attrs)
    if method.lower() == 'get':
        return form
    return form + HTML.div(hidden(session_csrf_secret_name, session_csrf_secret_token()), style="display: none;")


#
# Flash messages, stored in cookie
#

class _Message(object):
    """A message returned by ``pop_flash_messages()``.

    Converting the message to a string returns the message text. Instances
    also have the following attributes:

    * ``category``: the category specified when the message was created.
    * ``message``: the html-safe message text.
    """

    def __init__(self, category, message):
        self.category = category
        self.message = message


def _session_flash_messages(append=None, clear=False):
    """Manage a message queue in tg.session: return the current message queue
    after appending the given message, and possibly clearing the queue."""
    key = 'flash'
    if key in session:
        flash_messages = session[key]
    else:
        if append is None:  # common fast path - also used for clearing empty queue
            return []  # don't bother saving
        flash_messages = []
        session[key] = flash_messages
    if append is not None and append not in flash_messages:
        flash_messages.append(append)
    if clear:
        session.pop(key, None)
    session.save()
    return flash_messages


def flash(message, category, logf=None):
    """
    Show a message to the user _and_ log it through the specified function

    category: notice (default), warning, error, success
    logf: a custom log function - such as log.debug

    logf defaults to log.info, unless category equals 'success', in which
    case logf defaults to log.debug.
    """
    assert category in ('error', 'success', 'warning'), category
    if hasattr(message, '__html__'):
        # render to HTML for storing in cookie
        safe_message = str(message)
    else:
        # Apply str - the message might be an exception with __str__
        # Escape, so we can trust the result without further escaping, without any risk of injection
        safe_message = html_escape(str(message))
    if logf is None:
        logf = log.info
        if category == 'success':
            logf = log.debug

    logf('Flash %s: %s', category, safe_message)

    _session_flash_messages(append=(category, safe_message))


def pop_flash_messages():
    """Return all accumulated messages and delete them from the session.

    The return value is a list of ``Message`` objects.
    """
    return [_Message(category, message) for category, message in _session_flash_messages(clear=True)]


#
# Generic-ish formatting and markup
#

def js(value):
    """Convert Python value to the corresponding JavaScript representation.

    This is necessary to safely insert arbitrary values into HTML <script>
    sections e.g. using Mako template expression substitution.

    Note: Rather than using this function, it's preferable to avoid the
    insertion of values into HTML <script> sections altogether. Instead,
    data should (to the extent possible) be passed to JavaScript using
    data attributes or AJAX calls, eliminating the need for JS specific
    escaping.

    Note: This is not safe for use in attributes (e.g. onclick), because
    quotes are not escaped.

    Because the rules for parsing <script> varies between XHTML (where
    normal rules apply for any special characters) and HTML (where
    entities are not interpreted, but the literal string "</script>"
    is forbidden), the function ensures that the result never contains
    '&', '<' and '>', thus making it safe in both those contexts (but
    not in attributes).
    """
    return literal(
        ('(' + json.dumps(value) + ')')
        # In JSON, the following can only appear in string literals.
        .replace('&', r'\x26')
        .replace('<', r'\x3c')
        .replace('>', r'\x3e')
    )


def jshtml(val):
    """HTML escapes a string value, then converts the resulting string
    to its corresponding JavaScript representation (see `js`).

    This is used when a plain-text string (possibly containing special
    HTML characters) will be used by a script in an HTML context (e.g.
    element.innerHTML or jQuery's 'html' method).

    If in doubt, err on the side of using `jshtml` over `js`, since it's
    better to escape too much than too little.
    """
    return js(escape(val))
