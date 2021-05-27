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

import datetime
import json
import logging
import random
import re

from dateutil import relativedelta
from tg import request, session
from tg.i18n import ugettext as _
from tg.i18n import ungettext
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


url_re = re.compile(r'''\bhttps?://(?:[\da-zA-Z0-9@:.-]+)'''
                    r'''(?:[/a-zA-Z0-9_=@#~&+%.,:;?!*()-]*[/a-zA-Z0-9_=@#~])?''')


# Must match regexp in kallithea/public/js/base.js MentionsAutoComplete()
# Check char before @ - it must not look like we are in an email addresses.
# Matching is greedy so we don't have to look beyond the end.
MENTIONS_REGEX = re.compile(r'(?:^|(?<=[^a-zA-Z0-9]))@([a-zA-Z0-9][-_.a-zA-Z0-9]*[a-zA-Z0-9])')


def extract_mentioned_usernames(text):
    r"""
    Returns list of (possible) usernames @mentioned in given text.

    >>> extract_mentioned_usernames('@1-2.a_X,@1234 not@not @ddd@not @n @ee @ff @gg, @gg;@hh @n\n@zz,')
    ['1-2.a_X', '1234', 'ddd', 'ee', 'ff', 'gg', 'gg', 'hh', 'zz']
    """
    return MENTIONS_REGEX.findall(text)


_URLIFY_RE = re.compile(r'''
# URL markup
(?P<url>%s) |
# @mention markup
(?P<mention>%s) |
# Changeset hash markup
(?<!\w|[-_])
  (?P<hash>[0-9a-f]{12,40})
(?!\w|[-_]) |
# Markup of *bold text*
(?:
  (?:^|(?<=\s))
  (?P<bold> [*] (?!\s) [^*\n]* (?<!\s) [*] )
  (?![*\w])
) |
# "Stylize" markup
\[see\ \=&gt;\ *(?P<seen>[a-zA-Z0-9\/\=\?\&\ \:\/\.\-]*)\] |
\[license\ \=&gt;\ *(?P<license>[a-zA-Z0-9\/\=\?\&\ \:\/\.\-]*)\] |
\[(?P<tagtype>requires|recommends|conflicts|base)\ \=&gt;\ *(?P<tagvalue>[a-zA-Z0-9\-\/]*)\] |
\[(?:lang|language)\ \=&gt;\ *(?P<lang>[a-zA-Z\-\/\#\+]*)\] |
\[(?P<tag>[a-z]+)\]
''' % (url_re.pattern, MENTIONS_REGEX.pattern),
    re.VERBOSE | re.MULTILINE | re.IGNORECASE)


def urlify_text(s, repo_name=None, link_=None, truncate=None, stylize=False, truncatef=truncate):
    """
    Parses given text message and make literal html with markup.
    The text will be truncated to the specified length.
    Hashes are turned into changeset links to specified repository.
    URLs links to what they say.
    Issues are linked to given issue-server.
    If link_ is provided, all text not already linking somewhere will link there.
    >>> urlify_text("Urlify http://example.com/ and 'https://example.com' *and* <b>markup/b>")
    literal('Urlify <a href="http://example.com/">http://example.com/</a> and &#39;<a href="https://example.com&apos">https://example.com&apos</a>; <b>*and*</b> &lt;b&gt;markup/b&gt;')
    """

    def _replace(match_obj):
        match_url = match_obj.group('url')
        if match_url is not None:
            return '<a href="%(url)s">%(url)s</a>' % {'url': match_url}
        mention = match_obj.group('mention')
        if mention is not None:
            return '<b>%s</b>' % mention
        hash_ = match_obj.group('hash')
        if hash_ is not None and repo_name is not None:
            return '<a class="changeset_hash" href="%(url)s">%(hash)s</a>' % {
                 'url': url('changeset_home', repo_name=repo_name, revision=hash_),
                 'hash': hash_,
                }
        bold = match_obj.group('bold')
        if bold is not None:
            return '<b>*%s*</b>' % _urlify(bold[1:-1])
        if stylize:
            seen = match_obj.group('seen')
            if seen:
                return '<div class="label label-meta" data-tag="see">see =&gt; %s</div>' % seen
            license = match_obj.group('license')
            if license:
                return '<div class="label label-meta" data-tag="license"><a href="http://www.opensource.org/licenses/%s">%s</a></div>' % (license, license)
            tagtype = match_obj.group('tagtype')
            if tagtype:
                tagvalue = match_obj.group('tagvalue')
                return '<div class="label label-meta" data-tag="%s">%s =&gt; <a href="/%s">%s</a></div>' % (tagtype, tagtype, tagvalue, tagvalue)
            lang = match_obj.group('lang')
            if lang:
                return '<div class="label label-meta" data-tag="lang">%s</div>' % lang
            tag = match_obj.group('tag')
            if tag:
                return '<div class="label label-meta" data-tag="%s">%s</div>' % (tag, tag)
        return match_obj.group(0)

    def _urlify(s):
        """
        Extract urls from text and make html links out of them
        """
        return _URLIFY_RE.sub(_replace, s)

    if truncate is None:
        s = s.rstrip()
    else:
        s = truncatef(s, truncate, whole_word=True)
    s = html_escape(s)
    s = _urlify(s)
    if repo_name is not None:
        s = _urlify_issues(s, repo_name)
    if link_ is not None:
        # make href around everything that isn't a href already
        s = _linkify_others(s, link_)
    s = s.replace('\r\n', '<br/>').replace('\n', '<br/>')
    # Turn HTML5 into more valid HTML4 as required by some mail readers.
    # (This is not done in one step in html_escape, because character codes like
    # &#123; risk to be seen as an issue reference due to the presence of '#'.)
    s = s.replace("&apos;", "&#39;")
    return literal(s)


def _linkify_others(t, l):
    """Add a default link to html with links.
    HTML doesn't allow nesting of links, so the outer link must be broken up
    in pieces and give space for other links.
    """
    urls = re.compile(r'(\<a.*?\<\/a\>)',)
    links = []
    for e in urls.split(t):
        if e.strip() and not urls.match(e):
            links.append('<a class="message-link" href="%s">%s</a>' % (l, e))
        else:
            links.append(e)
    return ''.join(links)


# Global variable that will hold the actual _urlify_issues function body.
# Will be set on first use when the global configuration has been read.
_urlify_issues_f = None


def _urlify_issues(newtext, repo_name):
    """Urlify issue references according to .ini configuration"""
    global _urlify_issues_f
    if _urlify_issues_f is None:
        assert kallithea.CONFIG['sqlalchemy.url'] # make sure config has been loaded

        # Build chain of urlify functions, starting with not doing any transformation
        def tmp_urlify_issues_f(s):
            return s

        issue_pat_re = re.compile(r'issue_pat(.*)')
        for k in kallithea.CONFIG:
            # Find all issue_pat* settings that also have corresponding server_link and prefix configuration
            m = issue_pat_re.match(k)
            if m is None:
                continue
            suffix = m.group(1)
            issue_pat = kallithea.CONFIG.get(k)
            issue_server_link = kallithea.CONFIG.get('issue_server_link%s' % suffix)
            issue_sub = kallithea.CONFIG.get('issue_sub%s' % suffix)
            issue_prefix = kallithea.CONFIG.get('issue_prefix%s' % suffix)
            if issue_prefix:
                log.error('found unsupported issue_prefix%s = %r - use issue_sub%s instead', suffix, issue_prefix, suffix)
            if not issue_pat:
                log.error('skipping incomplete issue pattern %r: it needs a regexp', k)
                continue
            if not issue_server_link:
                log.error('skipping incomplete issue pattern %r: it needs issue_server_link%s', k, suffix)
                continue
            if issue_sub is None: # issue_sub can be empty but should be present
                log.error('skipping incomplete issue pattern %r: it needs (a potentially empty) issue_sub%s', k, suffix)
                continue

            # Wrap tmp_urlify_issues_f with substitution of this pattern, while making sure all loop variables (and compiled regexpes) are bound
            try:
                issue_re = re.compile(issue_pat)
            except re.error as e:
                log.error('skipping invalid issue pattern %r: %r -> %r %r. Error: %s', k, issue_pat, issue_server_link, issue_sub, str(e))
                continue

            log.debug('issue pattern %r: %r -> %r %r', k, issue_pat, issue_server_link, issue_sub)

            def issues_replace(match_obj,
                               issue_server_link=issue_server_link, issue_sub=issue_sub):
                try:
                    issue_url = match_obj.expand(issue_server_link)
                except (IndexError, re.error) as e:
                    log.error('invalid issue_url setting %r -> %r %r. Error: %s', issue_pat, issue_server_link, issue_sub, str(e))
                    issue_url = issue_server_link
                issue_url = issue_url.replace('{repo}', repo_name)
                issue_url = issue_url.replace('{repo_name}', repo_name.split(kallithea.URL_SEP)[-1])
                # if issue_sub is empty use the matched issue reference verbatim
                if not issue_sub:
                    issue_text = match_obj.group()
                else:
                    try:
                        issue_text = match_obj.expand(issue_sub)
                    except (IndexError, re.error) as e:
                        log.error('invalid issue_sub setting %r -> %r %r. Error: %s', issue_pat, issue_server_link, issue_sub, str(e))
                        issue_text = match_obj.group()

                return (
                    '<a class="issue-tracker-link" href="%(url)s">'
                    '%(text)s'
                    '</a>'
                    ) % {
                     'url': issue_url,
                     'text': issue_text,
                    }

            def tmp_urlify_issues_f(s, issue_re=issue_re, issues_replace=issues_replace, chain_f=tmp_urlify_issues_f):
                return issue_re.sub(issues_replace, chain_f(s))

        # Set tmp function globally - atomically
        _urlify_issues_f = tmp_urlify_issues_f

    return _urlify_issues_f(newtext)


def render_w_mentions(source, repo_name=None):
    """
    Render plain text with revision hashes and issue references urlified
    and with @mention highlighting.
    """
    s = urlify_text(source, repo_name=repo_name)
    return literal('<div class="formatted-fixed">%s</div>' % s)


#
# Simple filters
#

def shorter(s, size=20, firstline=False, postfix='...'):
    """Truncate s to size, including the postfix string if truncating.
    If firstline, truncate at newline.
    """
    if firstline:
        s = s.split('\n', 1)[0].rstrip()
    if len(s) > size:
        return s[:size - len(postfix)] + postfix
    return s


def age(prevdate, show_short_version=False, now=None):
    """
    turns a datetime into an age string.
    If show_short_version is True, then it will generate a not so accurate but shorter string,
    example: 2days ago, instead of 2 days and 23 hours ago.

    :param prevdate: datetime object
    :param show_short_version: if it should approximate the date and return a shorter string
    :rtype: str
    :returns: str words describing age
    """
    now = now or datetime.datetime.now()
    order = ['year', 'month', 'day', 'hour', 'minute', 'second']
    deltas = {}
    future = False

    if prevdate > now:
        now, prevdate = prevdate, now
        future = True
    if future:
        prevdate = prevdate.replace(microsecond=0)
    # Get date parts deltas
    for part in order:
        d = relativedelta.relativedelta(now, prevdate)
        deltas[part] = getattr(d, part + 's')

    # Fix negative offsets (there is 1 second between 10:59:59 and 11:00:00,
    # not 1 hour, -59 minutes and -59 seconds)
    for num, length in [(5, 60), (4, 60), (3, 24)]:  # seconds, minutes, hours
        part = order[num]
        carry_part = order[num - 1]

        if deltas[part] < 0:
            deltas[part] += length
            deltas[carry_part] -= 1

    # Same thing for days except that the increment depends on the (variable)
    # number of days in the month
    month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if deltas['day'] < 0:
        if prevdate.month == 2 and (prevdate.year % 4 == 0 and
            (prevdate.year % 100 != 0 or prevdate.year % 400 == 0)
        ):
            deltas['day'] += 29
        else:
            deltas['day'] += month_lengths[prevdate.month - 1]

        deltas['month'] -= 1

    if deltas['month'] < 0:
        deltas['month'] += 12
        deltas['year'] -= 1

    # In short version, we want nicer handling of ages of more than a year
    if show_short_version:
        if deltas['year'] == 1:
            # ages between 1 and 2 years: show as months
            deltas['month'] += 12
            deltas['year'] = 0
        if deltas['year'] >= 2:
            # ages 2+ years: round
            if deltas['month'] > 6:
                deltas['year'] += 1
                deltas['month'] = 0

    # Format the result
    fmt_funcs = {
        'year': lambda d: ungettext('%d year', '%d years', d) % d,
        'month': lambda d: ungettext('%d month', '%d months', d) % d,
        'day': lambda d: ungettext('%d day', '%d days', d) % d,
        'hour': lambda d: ungettext('%d hour', '%d hours', d) % d,
        'minute': lambda d: ungettext('%d minute', '%d minutes', d) % d,
        'second': lambda d: ungettext('%d second', '%d seconds', d) % d,
    }

    for i, part in enumerate(order):
        value = deltas[part]
        if value == 0:
            continue

        if i < 5:
            sub_part = order[i + 1]
            sub_value = deltas[sub_part]
        else:
            sub_value = 0

        if sub_value == 0 or show_short_version:
            if future:
                return _('in %s') % fmt_funcs[part](value)
            else:
                return _('%s ago') % fmt_funcs[part](value)
        if future:
            return _('in %s and %s') % (fmt_funcs[part](value),
                fmt_funcs[sub_part](sub_value))
        else:
            return _('%s and %s ago') % (fmt_funcs[part](value),
                fmt_funcs[sub_part](sub_value))

    return _('just now')


def fmt_date(date):
    if date:
        return date.strftime("%Y-%m-%d %H:%M:%S")
    return ""


def capitalize(x):
    return x.capitalize()


def short_id(x):
    return x[:12]
