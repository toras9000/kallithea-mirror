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
Helper functions

Consists of functions to typically be used within templates, but also
available to Controllers. This module is available to both as 'h'.
"""
import hashlib
import logging
import re
import textwrap
import urllib.parse

from beaker.cache import cache_region
from pygments import highlight as code_highlight
from pygments.formatters.html import HtmlFormatter
from tg import tmpl_context as c
from tg.i18n import ugettext as _

import kallithea
from kallithea.lib.annotate import annotate_highlight
from kallithea.lib.auth import HasPermissionAny, HasRepoGroupPermissionLevel, HasRepoPermissionLevel
from kallithea.lib.diffs import BIN_FILENODE, CHMOD_FILENODE, DEL_FILENODE, MOD_FILENODE, NEW_FILENODE, RENAMED_FILENODE
from kallithea.lib.pygmentsutils import get_custom_lexer
from kallithea.lib.utils2 import AttributeDict, asbool, credentials_filter, link_to_ref, safe_bytes, safe_int, safe_str, time_to_datetime
from kallithea.lib.vcs.backends.base import BaseChangeset, EmptyChangeset
from kallithea.lib.vcs.exceptions import ChangesetDoesNotExistError
from kallithea.lib.vcs.utils import author_email, author_name
from kallithea.lib.webutils import (HTML, Option, age, canonical_url, checkbox, chop_at, end_form, escape, fmt_date, form, format_byte_size, hidden, js, jshtml,
                                    link_to, literal, password, pop_flash_messages, radio, render_w_mentions, reset, safeid, select, session_csrf_secret_name,
                                    session_csrf_secret_token, shorter, submit, text, textarea, url, urlify_text, wrap_paragraphs)
from kallithea.model import db
from kallithea.model.changeset_status import ChangesetStatusModel


# mute pyflakes "imported but unused"
# from webutils
assert Option
assert age
assert canonical_url
assert checkbox
assert chop_at
assert end_form
assert fmt_date
assert form
assert format_byte_size
assert hidden
assert js
assert jshtml
assert password
assert pop_flash_messages
assert radio
assert render_w_mentions
assert reset
assert safeid
assert select
assert session_csrf_secret_name
assert session_csrf_secret_token
assert shorter
assert submit
assert text
assert textarea
assert urlify_text
assert wrap_paragraphs
# from kallithea.lib.auth
assert HasPermissionAny
assert HasRepoGroupPermissionLevel
assert HasRepoPermissionLevel
# from utils2
assert credentials_filter
assert link_to_ref
assert time_to_datetime
# from vcs
assert EmptyChangeset


log = logging.getLogger(__name__)


def FID(raw_id, path):
    """
    Creates a unique ID for filenode based on it's hash of path and revision
    it's safe to use in urls
    """
    return 'C-%s-%s' % (short_id(raw_id), hashlib.md5(safe_bytes(path)).hexdigest()[:12])


def get_ignore_whitespace_diff(GET):
    """Return true if URL requested whitespace to be ignored"""
    return bool(GET.get('ignorews'))


def ignore_whitespace_link(GET, anchor=None):
    """Return snippet with link to current URL with whitespace ignoring toggled"""
    params = dict(GET)  # ignoring duplicates
    if get_ignore_whitespace_diff(GET):
        params.pop('ignorews')
        title = _("Show whitespace changes")
    else:
        params['ignorews'] = '1'
        title = _("Ignore whitespace changes")
    params['anchor'] = anchor
    return link_to(
        literal('<i class="icon-strike"></i>'),
        url.current(**params),
        title=title,
        **{'data-toggle': 'tooltip'})


def get_diff_context_size(GET):
    """Return effective context size requested in URL"""
    return safe_int(GET.get('context'), default=3)


def increase_context_link(GET, anchor=None):
    """Return snippet with link to current URL with double context size"""
    context = get_diff_context_size(GET) * 2
    params = dict(GET)  # ignoring duplicates
    params['context'] = str(context)
    params['anchor'] = anchor
    return link_to(
        literal('<i class="icon-sort"></i>'),
        url.current(**params),
        title=_('Increase diff context to %(num)s lines') % {'num': context},
        **{'data-toggle': 'tooltip'})


def files_breadcrumbs(repo_name, rev, paths):
    url_l = [link_to(repo_name, url('files_home',
                                    repo_name=repo_name,
                                    revision=rev, f_path=''),
                     class_='ypjax-link')]
    paths_l = paths.split('/')
    for cnt, p in enumerate(paths_l):
        if p != '':
            url_l.append(link_to(p,
                                 url('files_home',
                                     repo_name=repo_name,
                                     revision=rev,
                                     f_path='/'.join(paths_l[:cnt + 1])
                                     ),
                                 class_='ypjax-link'
                                 )
                         )
    return literal('/'.join(url_l))


class CodeHtmlFormatter(HtmlFormatter):
    """
    My code Html Formatter for source codes
    """

    def wrap(self, source, outfile):
        return self._wrap_div(self._wrap_pre(self._wrap_code(source)))

    def _wrap_code(self, source):
        for cnt, it in enumerate(source):
            i, t = it
            t = '<span id="L%s">%s</span>' % (cnt + 1, t)
            yield i, t

    def _wrap_tablelinenos(self, inner):
        inner_lines = []
        lncount = 0
        for t, line in inner:
            if t:
                lncount += 1
            inner_lines.append(line)

        fl = self.linenostart
        mw = len(str(lncount + fl - 1))
        sp = self.linenospecial
        st = self.linenostep
        la = self.lineanchors
        aln = self.anchorlinenos
        nocls = self.noclasses
        if sp:
            lines = []

            for i in range(fl, fl + lncount):
                if i % st == 0:
                    if i % sp == 0:
                        if aln:
                            lines.append('<a href="#%s%d" class="special">%*d</a>' %
                                         (la, i, mw, i))
                        else:
                            lines.append('<span class="special">%*d</span>' % (mw, i))
                    else:
                        if aln:
                            lines.append('<a href="#%s%d">%*d</a>' % (la, i, mw, i))
                        else:
                            lines.append('%*d' % (mw, i))
                else:
                    lines.append('')
            ls = '\n'.join(lines)
        else:
            lines = []
            for i in range(fl, fl + lncount):
                if i % st == 0:
                    if aln:
                        lines.append('<a href="#%s%d">%*d</a>' % (la, i, mw, i))
                    else:
                        lines.append('%*d' % (mw, i))
                else:
                    lines.append('')
            ls = '\n'.join(lines)

        # in case you wonder about the seemingly redundant <div> here: since the
        # content in the other cell also is wrapped in a div, some browsers in
        # some configurations seem to mess up the formatting...
        if nocls:
            yield 0, ('<table class="%stable">' % self.cssclass +
                      '<tr><td><div class="linenodiv">'
                      '<pre>' + ls + '</pre></div></td>'
                      '<td id="hlcode" class="code">')
        else:
            yield 0, ('<table class="%stable">' % self.cssclass +
                      '<tr><td class="linenos"><div class="linenodiv">'
                      '<pre>' + ls + '</pre></div></td>'
                      '<td id="hlcode" class="code">')
        yield 0, ''.join(inner_lines)
        yield 0, '</td></tr></table>'


_whitespace_re = re.compile(r'(\t)|( )(?=\n|</div>)')


def _markup_whitespace(m):
    groups = m.groups()
    if groups[0]:
        return '<u>\t</u>'
    if groups[1]:
        return ' <i></i>'


def markup_whitespace(s):
    return _whitespace_re.sub(_markup_whitespace, s)


def pygmentize(filenode, **kwargs):
    """
    pygmentize function using pygments

    :param filenode:
    """
    lexer = get_custom_lexer(filenode.extension) or filenode.lexer
    return literal(markup_whitespace(
        code_highlight(safe_str(filenode.content), lexer, CodeHtmlFormatter(**kwargs))))


def hsv_to_rgb(h, s, v):
    if s == 0.0:
        return v, v, v
    i = int(h * 6.0)  # XXX assume int() truncates!
    f = (h * 6.0) - i
    p = v * (1.0 - s)
    q = v * (1.0 - s * f)
    t = v * (1.0 - s * (1.0 - f))
    i = i % 6
    if i == 0:
        return v, t, p
    if i == 1:
        return q, v, p
    if i == 2:
        return p, v, t
    if i == 3:
        return p, q, v
    if i == 4:
        return t, p, v
    if i == 5:
        return v, p, q


def gen_color(n=10000):
    """generator for getting n of evenly distributed colors using
    hsv color and golden ratio. It always return same order of colors

    :returns: RGB tuple
    """

    golden_ratio = 0.618033988749895
    h = 0.22717784590367374

    for _unused in range(n):
        h += golden_ratio
        h %= 1
        HSV_tuple = [h, 0.95, 0.95]
        RGB_tuple = hsv_to_rgb(*HSV_tuple)
        yield [str(int(x * 256)) for x in RGB_tuple]


def pygmentize_annotation(repo_name, filenode, **kwargs):
    """
    pygmentize function for annotation

    :param filenode:
    """
    cgenerator = gen_color()
    color_dict = {}

    def get_color_string(cs):
        if cs in color_dict:
            col = color_dict[cs]
        else:
            col = color_dict[cs] = next(cgenerator)
        return "color: rgb(%s)! important;" % (', '.join(col))

    def url_func(changeset):
        author = escape(changeset.author)
        date = changeset.date
        message = escape(changeset.message)
        tooltip_html = ("<b>Author:</b> %s<br/>"
                        "<b>Date:</b> %s</b><br/>"
                        "<b>Message:</b> %s") % (author, date, message)

        lnk_format = show_id(changeset)
        uri = link_to(
                lnk_format,
                url('changeset_home', repo_name=repo_name,
                    revision=changeset.raw_id),
                style=get_color_string(changeset.raw_id),
                **{'data-toggle': 'popover',
                   'data-content': tooltip_html}
              )

        uri += '\n'
        return uri

    return literal(markup_whitespace(annotate_highlight(filenode, url_func, **kwargs)))


def capitalize(x):
    return x.capitalize()

def short_id(x):
    return x[:12]


def show_id(cs):
    """
    Configurable function that shows ID
    by default it's r123:fffeeefffeee

    :param cs: changeset instance
    """
    def_len = safe_int(kallithea.CONFIG.get('show_sha_length', 12))
    show_rev = asbool(kallithea.CONFIG.get('show_revision_number', False))

    raw_id = cs.raw_id[:def_len]
    if show_rev:
        return 'r%s:%s' % (cs.revision, raw_id)
    else:
        return raw_id


@cache_region('long_term', 'user_attr_or_none')
def user_attr_or_none(author, show_attr):
    """Try to match email part of VCS committer string with a local user and return show_attr
    - or return None if user not found"""
    email = author_email(author)
    if email:
        user = db.User.get_by_email(email)
        if user is not None:
            return getattr(user, show_attr)
    return None


def email_or_none(author):
    """Try to match email part of VCS committer string with a local user.
    Return primary email of user, email part of the specified author name, or None."""
    if not author:
        return None
    email = user_attr_or_none(author, 'email')
    if email is not None:
        return email # always use user's main email address - not necessarily the one used to find user

    # extract email from the commit string
    email = author_email(author)
    if email:
        return email

    # No valid email, not a valid user in the system, none!
    return None


def person(author, show_attr="username"):
    """Find the user identified by 'author' string, return one of the users attributes,
    default to the username attribute, None if there is no user"""
    value = user_attr_or_none(author, show_attr)
    if value is not None:
        return value

    # Still nothing?  Just pass back the author name if any, else the email
    return author_name(author) or author_email(author)


def person_by_id(id_, show_attr="username"):
    # maybe it's an ID ?
    if str(id_).isdigit() or isinstance(id_, int):
        id_ = int(id_)
        user = db.User.get(id_)
        if user is not None:
            return getattr(user, show_attr)
    return id_


def boolicon(value):
    """Returns boolean value of a value, represented as small html image of true/false
    icons

    :param value: value
    """

    if value:
        return HTML.tag('i', class_="icon-ok")
    else:
        return HTML.tag('i', class_="icon-minus-circled")


def action_parser(user_log, feed=False, parse_cs=False):
    """
    This helper will action_map the specified string action into translated
    fancy names with icons and links

    :param user_log: user log instance
    :param feed: use output for feeds (no html and fancy icons)
    :param parse_cs: parse Changesets into VCS instances
    """

    action = user_log.action
    action_params = ' '

    x = action.split(':')

    if len(x) > 1:
        action, action_params = x

    def get_cs_links():
        revs_limit = 3  # display this amount always
        revs_top_limit = 50  # show upto this amount of changesets hidden
        revs_ids = action_params.split(',')
        deleted = user_log.repository is None
        if deleted:
            return ','.join(revs_ids)

        repo_name = user_log.repository.repo_name

        def lnk(rev, repo_name):
            lazy_cs = False
            title_ = None
            url_ = '#'
            if isinstance(rev, BaseChangeset) or isinstance(rev, AttributeDict):
                if rev.op and rev.ref_name:
                    if rev.op == 'delete_branch':
                        lbl = _('Deleted branch: %s') % rev.ref_name
                    elif rev.op == 'tag':
                        lbl = _('Created tag: %s') % rev.ref_name
                    else:
                        lbl = 'Unknown operation %s' % rev.op
                else:
                    lazy_cs = True
                    lbl = rev.short_id[:8]
                    url_ = url('changeset_home', repo_name=repo_name,
                               revision=rev.raw_id)
            else:
                # changeset cannot be found - it might have been stripped or removed
                lbl = rev[:12]
                title_ = _('Changeset %s not found') % lbl
            if parse_cs:
                return link_to(lbl, url_, title=title_, **{'data-toggle': 'tooltip'})
            return link_to(lbl, url_, class_='lazy-cs' if lazy_cs else '',
                           **{'data-raw_id': rev.raw_id, 'data-repo_name': repo_name})

        def _get_op(rev_txt):
            _op = None
            _name = rev_txt
            if len(rev_txt.split('=>')) == 2:
                _op, _name = rev_txt.split('=>')
            return _op, _name

        revs = []
        if len([v for v in revs_ids if v != '']) > 0:
            repo = None
            for rev in revs_ids[:revs_top_limit]:
                _op, _name = _get_op(rev)

                # we want parsed changesets, or new log store format is bad
                if parse_cs:
                    try:
                        if repo is None:
                            repo = user_log.repository.scm_instance
                        _rev = repo.get_changeset(rev)
                        revs.append(_rev)
                    except ChangesetDoesNotExistError:
                        log.error('cannot find revision %s in this repo', rev)
                        revs.append(rev)
                else:
                    _rev = AttributeDict({
                        'short_id': rev[:12],
                        'raw_id': rev,
                        'message': '',
                        'op': _op,
                        'ref_name': _name
                    })
                    revs.append(_rev)
        cs_links = [" " + ', '.join(
            [lnk(rev, repo_name) for rev in revs[:revs_limit]]
        )]
        _op1, _name1 = _get_op(revs_ids[0])
        _op2, _name2 = _get_op(revs_ids[-1])

        _rev = '%s...%s' % (_name1, _name2)

        compare_view = (
            ' <div class="compare_view" data-toggle="tooltip" title="%s">'
            '<a href="%s">%s</a> </div>' % (
                _('Show all combined changesets %s->%s') % (
                    revs_ids[0][:12], revs_ids[-1][:12]
                ),
                url('changeset_home', repo_name=repo_name,
                    revision=_rev
                ),
                _('Compare view')
            )
        )

        # if we have exactly one more than normally displayed
        # just display it, takes less space than displaying
        # "and 1 more revisions"
        if len(revs_ids) == revs_limit + 1:
            cs_links.append(", " + lnk(revs[revs_limit], repo_name))

        # hidden-by-default ones
        if len(revs_ids) > revs_limit + 1:
            uniq_id = revs_ids[0]
            html_tmpl = (
                '<span> %s <a class="show_more" id="_%s" '
                'href="#more">%s</a> %s</span>'
            )
            if not feed:
                cs_links.append(html_tmpl % (
                      _('and'),
                      uniq_id, _('%s more') % (len(revs_ids) - revs_limit),
                      _('revisions')
                    )
                )

            if not feed:
                html_tmpl = '<span id="%s" style="display:none">, %s </span>'
            else:
                html_tmpl = '<span id="%s"> %s </span>'

            morelinks = ', '.join(
              [lnk(rev, repo_name) for rev in revs[revs_limit:]]
            )

            if len(revs_ids) > revs_top_limit:
                morelinks += ', ...'

            cs_links.append(html_tmpl % (uniq_id, morelinks))
        if len(revs) > 1:
            cs_links.append(compare_view)
        return ''.join(cs_links)

    def get_fork_name():
        repo_name = action_params
        url_ = url('summary_home', repo_name=repo_name)
        return _('Fork name %s') % link_to(action_params, url_)

    def get_user_name():
        user_name = action_params
        return user_name

    def get_users_group():
        group_name = action_params
        return group_name

    def get_pull_request():
        pull_request_id = action_params
        nice_id = db.PullRequest.make_nice_id(pull_request_id)

        deleted = user_log.repository is None
        if deleted:
            repo_name = user_log.repository_name
        else:
            repo_name = user_log.repository.repo_name

        return link_to(_('Pull request %s') % nice_id,
                    url('pullrequest_show', repo_name=repo_name,
                    pull_request_id=pull_request_id))

    def get_archive_name():
        archive_name = action_params
        return archive_name

    # action : translated str, callback(extractor), icon
    action_map = {
        'user_deleted_repo':           (_('[deleted] repository'),
                                        None, 'icon-trashcan'),
        'user_created_repo':           (_('[created] repository'),
                                        None, 'icon-plus'),
        'user_created_fork':           (_('[created] repository as fork'),
                                        None, 'icon-fork'),
        'user_forked_repo':            (_('[forked] repository'),
                                        get_fork_name, 'icon-fork'),
        'user_updated_repo':           (_('[updated] repository'),
                                        None, 'icon-pencil'),
        'user_downloaded_archive':      (_('[downloaded] archive from repository'),
                                        get_archive_name, 'icon-download-cloud'),
        'admin_deleted_repo':          (_('[delete] repository'),
                                        None, 'icon-trashcan'),
        'admin_created_repo':          (_('[created] repository'),
                                        None, 'icon-plus'),
        'admin_forked_repo':           (_('[forked] repository'),
                                        None, 'icon-fork'),
        'admin_updated_repo':          (_('[updated] repository'),
                                        None, 'icon-pencil'),
        'admin_created_user':          (_('[created] user'),
                                        get_user_name, 'icon-user'),
        'admin_updated_user':          (_('[updated] user'),
                                        get_user_name, 'icon-user'),
        'admin_created_users_group':   (_('[created] user group'),
                                        get_users_group, 'icon-pencil'),
        'admin_updated_users_group':   (_('[updated] user group'),
                                        get_users_group, 'icon-pencil'),
        'user_commented_revision':     (_('[commented] on revision in repository'),
                                        get_cs_links, 'icon-comment'),
        'user_commented_pull_request': (_('[commented] on pull request for'),
                                        get_pull_request, 'icon-comment'),
        'user_closed_pull_request':    (_('[closed] pull request for'),
                                        get_pull_request, 'icon-ok'),
        'push':                        (_('[pushed] into'),
                                        get_cs_links, 'icon-move-up'),
        'push_local':                  (_('[committed via Kallithea] into repository'),
                                        get_cs_links, 'icon-pencil'),
        'push_remote':                 (_('[pulled from remote] into repository'),
                                        get_cs_links, 'icon-move-up'),
        'pull':                        (_('[pulled] from'),
                                        None, 'icon-move-down'),
        'started_following_repo':      (_('[started following] repository'),
                                        None, 'icon-heart'),
        'stopped_following_repo':      (_('[stopped following] repository'),
                                        None, 'icon-heart-empty'),
    }

    action_str = action_map.get(action, action)
    if feed:
        action = action_str[0].replace('[', '').replace(']', '')
    else:
        action = action_str[0] \
            .replace('[', '<b>') \
            .replace(']', '</b>')

    action_params_func = action_str[1] if callable(action_str[1]) else (lambda: "")

    def action_parser_icon():
        action = user_log.action
        action_params = None
        x = action.split(':')

        if len(x) > 1:
            action, action_params = x

        ico = action_map.get(action, ['', '', ''])[2]
        html = """<i class="%s"></i>""" % ico
        return literal(html)

    # returned callbacks we need to call to get
    return [lambda: literal(action), action_params_func, action_parser_icon]


#==============================================================================
# GRAVATAR URL
#==============================================================================
def gravatar_div(email_address, cls='', size=30, **div_attributes):
    """Return an html literal with a span around a gravatar if they are enabled.
    Extra keyword parameters starting with 'div_' will get the prefix removed
    and '_' changed to '-' and be used as attributes on the div. The default
    class is 'gravatar'.
    """
    if not c.visual.use_gravatar:
        return ''
    if 'div_class' not in div_attributes:
        div_attributes['div_class'] = "gravatar"
    attributes = []
    for k, v in sorted(div_attributes.items()):
        assert k.startswith('div_'), k
        attributes.append(' %s="%s"' % (k[4:].replace('_', '-'), escape(v)))
    return literal("""<span%s>%s</span>""" %
                   (''.join(attributes),
                    gravatar(email_address, cls=cls, size=size)))


def gravatar(email_address, cls='', size=30):
    """return html element of the gravatar

    This method will return an <img> with the resolution double the size (for
    retina screens) of the image. If the url returned from gravatar_url is
    empty then we fallback to using an icon.

    """
    if not c.visual.use_gravatar:
        return ''

    src = gravatar_url(email_address, size * 2)

    if src:
        # here it makes sense to use style="width: ..." (instead of, say, a
        # stylesheet) because we using this to generate a high-res (retina) size
        html = ('<i class="icon-gravatar {cls}"'
                ' style="font-size: {size}px;background-size: {size}px;background-image: url(\'{src}\')"'
                '></i>').format(cls=cls, size=size, src=src)

    else:
        # if src is empty then there was no gravatar, so we use a font icon
        html = ("""<i class="icon-user {cls}" style="font-size: {size}px;"></i>"""
            .format(cls=cls, size=size))

    return literal(html)


def gravatar_url(email_address, size=30, default=''):
    if not c.visual.use_gravatar:
        return ""

    _def = 'anonymous@kallithea-scm.org'  # default gravatar
    email_address = email_address or _def

    if email_address == _def:
        return default

    parsed_url = urllib.parse.urlparse(url.current(qualified=True))
    return (c.visual.gravatar_url or db.User.DEFAULT_GRAVATAR_URL) \
               .replace('{email}', email_address) \
               .replace('{md5email}', hashlib.md5(safe_bytes(email_address).lower()).hexdigest()) \
               .replace('{netloc}', parsed_url.netloc) \
               .replace('{scheme}', parsed_url.scheme) \
               .replace('{size}', str(size))


def changed_tooltip(nodes):
    """
    Generates a html string for changed nodes in changeset page.
    It limits the output to 30 entries

    :param nodes: LazyNodesGenerator
    """
    if nodes:
        pref = ': <br/> '
        suf = ''
        if len(nodes) > 30:
            suf = '<br/>' + _(' and %s more') % (len(nodes) - 30)
        return literal(pref + '<br/> '.join([x.path
                                             for x in nodes[:30]]) + suf)
    else:
        return ': ' + _('No files')


def fancy_file_stats(stats):
    """
    Displays a fancy two colored bar for number of added/deleted
    lines of code on file

    :param stats: two element list of added/deleted lines of code
    """

    a, d = stats['added'], stats['deleted']
    width = 100

    if stats['binary']:
        # binary mode
        lbl = ''
        bin_op = 1

        if BIN_FILENODE in stats['ops']:
            lbl = 'bin+'

        if NEW_FILENODE in stats['ops']:
            lbl += _('new file')
            bin_op = NEW_FILENODE
        elif MOD_FILENODE in stats['ops']:
            lbl += _('mod')
            bin_op = MOD_FILENODE
        elif DEL_FILENODE in stats['ops']:
            lbl += _('del')
            bin_op = DEL_FILENODE
        elif RENAMED_FILENODE in stats['ops']:
            lbl += _('rename')
            bin_op = RENAMED_FILENODE

        # chmod can go with other operations
        if CHMOD_FILENODE in stats['ops']:
            _org_lbl = _('chmod')
            lbl += _org_lbl if lbl.endswith('+') else '+%s' % _org_lbl

        #import ipdb;ipdb.set_trace()
        b_d = '<div class="bin bin%s progress-bar" style="width:100%%">%s</div>' % (bin_op, lbl)
        b_a = '<div class="bin bin1" style="width:0%"></div>'
        return literal('<div style="width:%spx" class="progress">%s%s</div>' % (width, b_a, b_d))

    t = stats['added'] + stats['deleted']
    unit = float(width) / (t or 1)

    # needs > 9% of width to be visible or 0 to be hidden
    a_p = max(9, unit * a) if a > 0 else 0
    d_p = max(9, unit * d) if d > 0 else 0
    p_sum = a_p + d_p

    if p_sum > width:
        # adjust the percentage to be == 100% since we adjusted to 9
        if a_p > d_p:
            a_p = a_p - (p_sum - width)
        else:
            d_p = d_p - (p_sum - width)

    a_v = a if a > 0 else ''
    d_v = d if d > 0 else ''

    d_a = '<div class="added progress-bar" style="width:%s%%">%s</div>' % (
        a_p, a_v
    )
    d_d = '<div class="deleted progress-bar" style="width:%s%%">%s</div>' % (
        d_p, d_v
    )
    return literal('<div class="progress" style="width:%spx">%s%s</div>' % (width, d_a, d_d))


def changeset_status(repo, revision):
    return ChangesetStatusModel().get_status(repo, revision)


def changeset_status_lbl(changeset_status):
    return db.ChangesetStatus.get_status_lbl(changeset_status)


def get_permission_name(key):
    return dict(db.Permission.PERMS).get(key)


def journal_filter_help():
    return _(textwrap.dedent('''
        Example filter terms:
            repository:vcs
            username:developer
            action:*push*
            ip:127.0.0.1
            date:20120101
            date:[20120101100000 TO 20120102]

        Generate wildcards using '*' character:
            "repository:vcs*" - search everything starting with 'vcs'
            "repository:*vcs*" - search for repository containing 'vcs'

        Optional AND / OR operators in queries
            "repository:vcs OR repository:test"
            "username:test AND repository:test*"
    '''))


def ip_range(ip_addr):
    s, e = db.UserIpMap._get_ip_range(ip_addr)
    return '%s - %s' % (s, e)
