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
kallithea.lib.diffs
~~~~~~~~~~~~~~~~~~~

Set of diffing helpers, previously part of vcs


This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Dec 4, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""
import difflib
import logging
import re

from tg.i18n import ugettext as _

from kallithea.lib import webutils
from kallithea.lib.utils2 import safe_str
from kallithea.lib.vcs.backends.base import EmptyChangeset
from kallithea.lib.vcs.exceptions import VCSError
from kallithea.lib.vcs.nodes import FileNode, SubModuleNode


log = logging.getLogger(__name__)


def _safe_id(idstring):
    r"""Make a string safe for including in an id attribute.

    The HTML spec says that id attributes 'must begin with
    a letter ([A-Za-z]) and may be followed by any number
    of letters, digits ([0-9]), hyphens ("-"), underscores
    ("_"), colons (":"), and periods (".")'. These regexps
    are slightly over-zealous, in that they remove colons
    and periods unnecessarily.

    Whitespace is transformed into underscores, and then
    anything which is not a hyphen or a character that
    matches \w (alphanumerics and underscore) is removed.

    """
    # Transform all whitespace to underscore
    idstring = re.sub(r'\s', "_", idstring)
    # Remove everything that is not a hyphen or a member of \w
    idstring = re.sub(r'(?!-)\W', "", idstring).lower()
    return idstring


def as_html(parsed_lines, table_class='code-difftable', line_class='line',
            old_lineno_class='lineno old', new_lineno_class='lineno new',
            no_lineno_class='lineno',
            code_class='code'):
    """
    Return given diff as html table with customized css classes
    """
    _html_empty = True
    _html = []
    _html.append('''<table class="%(table_class)s">\n''' % {
        'table_class': table_class
    })

    for file_info in parsed_lines:
        for chunk in file_info['chunks']:
            _html_empty = False
            for change in chunk:
                _html.append('''<tr class="%(lc)s %(action)s">\n''' % {
                    'lc': line_class,
                    'action': change['action']
                })
                if change['old_lineno'] or change['new_lineno']:
                    ###########################################################
                    # OLD LINE NUMBER
                    ###########################################################
                    anchor_old = "%(filename)s_o%(oldline_no)s" % {
                        'filename': _safe_id(file_info['filename']),
                        'oldline_no': change['old_lineno']
                    }
                    anchor_old_id = ''
                    if change['old_lineno']:
                        anchor_old_id = 'id="%s"' % anchor_old
                    _html.append('''\t<td %(a_id)s class="%(olc)s">''' % {
                        'a_id': anchor_old_id,
                        'olc': old_lineno_class,
                    })
                    _html.append('''<a href="%(url)s" data-pseudo-content="%(label)s"></a>''' % {
                        'label': change['old_lineno'],
                        'url': '#%s' % anchor_old,
                    })
                    _html.append('''</td>\n''')
                    ###########################################################
                    # NEW LINE NUMBER
                    ###########################################################
                    anchor_new = "%(filename)s_n%(newline_no)s" % {
                        'filename': _safe_id(file_info['filename']),
                        'newline_no': change['new_lineno']
                    }
                    anchor_new_id = ''
                    if change['new_lineno']:
                        anchor_new_id = 'id="%s"' % anchor_new
                    _html.append('''\t<td %(a_id)s class="%(nlc)s">''' % {
                        'a_id': anchor_new_id,
                        'nlc': new_lineno_class
                    })
                    _html.append('''<a href="%(url)s" data-pseudo-content="%(label)s"></a>''' % {
                        'label': change['new_lineno'],
                        'url': '#%s' % anchor_new,
                    })
                    _html.append('''</td>\n''')
                else:
                    ###########################################################
                    # NO LINE NUMBER
                    ###########################################################
                    anchor = "%(filename)s_%(context_lineno)s" % {
                        'filename': _safe_id(file_info['filename']),
                        'context_lineno': change['context_lineno'],
                    }
                    _html.append('''\t<td id="%(anchor)s" class="%(olc)s" colspan="2">''' % {
                        'anchor': anchor,
                        'olc': no_lineno_class,
                    })
                    _html.append('''</td>\n''')
                ###########################################################
                # CODE
                ###########################################################
                _html.append('''\t<td class="%(cc)s">''' % {
                    'cc': code_class,
                })
                _html.append('''\n\t\t<div class="add-bubble"><div>&nbsp;</div></div><pre>%(code)s</pre>\n''' % {
                    'code': change['line']
                })

                _html.append('''\t</td>''')
                _html.append('''\n</tr>\n''')
    _html.append('''</table>''')
    if _html_empty:
        return None
    return ''.join(_html)


def wrap_to_table(html):
    """Given a string with html, return it wrapped in a table, similar to what
    as_html returns."""
    return '''\
              <table class="code-difftable">
                <tr class="line">
                <td class="lineno new"></td>
                <td class="code"><pre>%s</pre></td>
                </tr>
              </table>''' % html


def html_diff(filenode_old, filenode_new, diff_limit=None,
                ignore_whitespace=True, line_context=3):
    """
    Returns a file diff as HTML wrapped into a table.
    Checks for diff_limit and presents a message if the diff is too big.
    """
    if filenode_old is None:
        filenode_old = FileNode(filenode_new.path, '', EmptyChangeset())

    op = None
    a_path = filenode_old.path # default, might be overriden by actual rename in diff
    if filenode_old.is_binary or filenode_new.is_binary:
        html_diff = wrap_to_table(_('Binary file'))
        stats = (0, 0)

    elif diff_limit != -1 and (
            diff_limit is None or
            (filenode_old.size < diff_limit and filenode_new.size < diff_limit)):

        raw_diff = get_gitdiff(filenode_old, filenode_new,
                                ignore_whitespace=ignore_whitespace,
                                context=line_context)
        diff_processor = DiffProcessor(raw_diff, html=True)
        if diff_processor.parsed: # there should be exactly one element, for the specified file
            f = diff_processor.parsed[0]
            op = f['operation']
            a_path = f['old_filename']

        html_diff = as_html(parsed_lines=diff_processor.parsed)
        stats = diff_processor.stat()

    else:
        html_diff = wrap_to_table(_('Changeset was too big and was cut off, use '
                               'diff menu to display this diff'))
        stats = (0, 0)

    if not html_diff:
        submodules = [o for o in [filenode_new, filenode_old] if isinstance(o, SubModuleNode)]
        if submodules:
            html_diff = wrap_to_table(webutils.escape('Submodule %r' % submodules[0]))
        else:
            html_diff = wrap_to_table(_('No changes detected'))

    cs1 = filenode_old.changeset.raw_id
    cs2 = filenode_new.changeset.raw_id

    return cs1, cs2, a_path, html_diff, stats, op


def get_gitdiff(filenode_old, filenode_new, ignore_whitespace=True, context=3):
    """
    Returns git style diff between given ``filenode_old`` and ``filenode_new``.
    """
    # make sure we pass in default context
    context = context or 3
    submodules = [o for o in [filenode_new, filenode_old] if isinstance(o, SubModuleNode)]
    if submodules:
        return b''

    for filenode in (filenode_old, filenode_new):
        if not isinstance(filenode, FileNode):
            raise VCSError("Given object should be FileNode object, not %s"
                % filenode.__class__)

    repo = filenode_new.changeset.repository
    old_raw_id = getattr(filenode_old.changeset, 'raw_id', repo.EMPTY_CHANGESET)
    new_raw_id = getattr(filenode_new.changeset, 'raw_id', repo.EMPTY_CHANGESET)

    vcs_gitdiff = get_diff(repo, old_raw_id, new_raw_id, filenode_new.path,
                           ignore_whitespace, context)
    return vcs_gitdiff


def get_diff(scm_instance, rev1, rev2, path=None, ignore_whitespace=False, context=3):
    """
    A thin wrapper around vcs lib get_diff.
    """
    try:
        return scm_instance.get_diff(rev1, rev2, path=path,
                                     ignore_whitespace=ignore_whitespace, context=context)
    except MemoryError:
        webutils.flash('MemoryError: Diff is too big', category='error')
        return b''


NEW_FILENODE = 1
DEL_FILENODE = 2
MOD_FILENODE = 3
RENAMED_FILENODE = 4
COPIED_FILENODE = 5
CHMOD_FILENODE = 6
BIN_FILENODE = 7


class DiffProcessor(object):
    """
    Give it a unified or git diff and it returns a list of the files that were
    mentioned in the diff together with a dict of meta information that
    can be used to render it in a HTML template or as text.
    """
    _diff_git_re = re.compile(b'^diff --git', re.MULTILINE)

    def __init__(self, diff, vcs='hg', diff_limit=None, html=True):
        """
        :param diff:   a text in diff format
        :param vcs: type of version control hg or git
        :param diff_limit: define the size of diff that is considered "big"
            based on that parameter cut off will be triggered, set to None
            to show full diff
        """
        if not isinstance(diff, bytes):
            raise Exception('Diff must be bytes - got %s' % type(diff))

        self._diff = memoryview(diff)
        self.adds = 0
        self.removes = 0
        self.diff_limit = diff_limit
        self.limited_diff = False
        self.vcs = vcs
        self.parsed = self._parse_gitdiff(html=html)

    def _parse_gitdiff(self, html):
        """Parse self._diff and return a list of dicts with meta info and chunks for each file.
        Might set limited_diff.
        Optionally, do an extra pass and to extra markup of one-liner changes.
        """
        _files = [] # list of dicts with meta info and chunks

        starts = [m.start() for m in self._diff_git_re.finditer(self._diff)]
        starts.append(len(self._diff))

        for start, end in zip(starts, starts[1:]):
            if self.diff_limit and end > self.diff_limit:
                self.limited_diff = True
                continue

            head, diff_lines = _get_header(self.vcs, self._diff[start:end])

            op = None
            stats = {
                'added': 0,
                'deleted': 0,
                'binary': False,
                'ops': {},
            }

            if head['deleted_file_mode']:
                op = 'removed'
                stats['binary'] = True
                stats['ops'][DEL_FILENODE] = 'deleted file'

            elif head['new_file_mode']:
                op = 'added'
                stats['binary'] = True
                stats['ops'][NEW_FILENODE] = 'new file %s' % head['new_file_mode']
            else:  # modify operation, can be cp, rename, chmod
                # CHMOD
                if head['new_mode'] and head['old_mode']:
                    op = 'modified'
                    stats['binary'] = True
                    stats['ops'][CHMOD_FILENODE] = ('modified file chmod %s => %s'
                                        % (head['old_mode'], head['new_mode']))
                # RENAME
                if (head['rename_from'] and head['rename_to']
                      and head['rename_from'] != head['rename_to']):
                    op = 'renamed'
                    stats['binary'] = True
                    stats['ops'][RENAMED_FILENODE] = ('file renamed from %s to %s'
                                    % (head['rename_from'], head['rename_to']))
                # COPY
                if head.get('copy_from') and head.get('copy_to'):
                    op = 'modified'
                    stats['binary'] = True
                    stats['ops'][COPIED_FILENODE] = ('file copied from %s to %s'
                                        % (head['copy_from'], head['copy_to']))
                # FALL BACK: detect missed old style add or remove
                if op is None:
                    if not head['a_file'] and head['b_file']:
                        op = 'added'
                        stats['binary'] = True
                        stats['ops'][NEW_FILENODE] = 'new file'

                    elif head['a_file'] and not head['b_file']:
                        op = 'removed'
                        stats['binary'] = True
                        stats['ops'][DEL_FILENODE] = 'deleted file'

                # it's not ADD not DELETE
                if op is None:
                    op = 'modified'
                    stats['binary'] = True
                    stats['ops'][MOD_FILENODE] = 'modified file'

            # a real non-binary diff
            if head['a_file'] or head['b_file']:
                chunks, added, deleted = _parse_lines(diff_lines)
                stats['binary'] = False
                stats['added'] = added
                stats['deleted'] = deleted
                # explicit mark that it's a modified file
                if op == 'modified':
                    stats['ops'][MOD_FILENODE] = 'modified file'
            else:  # Git binary patch (or empty diff)
                # Git binary patch
                if head['bin_patch']:
                    stats['ops'][BIN_FILENODE] = 'binary diff not shown'
                chunks = []

            if op == 'removed' and chunks:
                # a way of seeing deleted content could perhaps be nice - but
                # not with the current UI
                chunks = []

            # show helpful additional texts for mode change and renaming, but not for plain 'modified file'
            msgs = [
                {
                    'old_lineno': '',
                    'new_lineno': '',
                    'action': 'context',
                    'line': msg,
                }
                for op_, msg in stats['ops'].items()
                if op_ != MOD_FILENODE
            ]
            if msgs:
                chunks.insert(0, msgs)

            # enumerate 'context' lines that don't have new/old line numbers so they can be commented on
            context_lineno = 0
            for chunk in chunks:
                for change in chunk:
                    if not change['old_lineno'] and not change['new_lineno']:
                        change['context_lineno'] = context_lineno
                        context_lineno += 1

            _files.append({
                'old_filename':     head['a_path'],
                'filename':         head['b_path'],
                'old_revision':     head['a_blob_id'],
                'new_revision':     head['b_blob_id'],
                'chunks':           chunks,
                'operation':        op,
                'stats':            stats,
            })

        if not html:
            return _files

        for diff_data in _files:
            for chunk in diff_data['chunks']:
                for change in chunk:
                    change['line'] = _escaper(change['line'])
                # highlight inline changes when one del is followed by one add
                lineiter = iter(chunk)
                try:
                    peekline = next(lineiter)
                    while True:
                        # find a first del line
                        while peekline['action'] != 'del':
                            peekline = next(lineiter)
                        delline = peekline
                        peekline = next(lineiter)
                        # if not followed by add, eat all following del lines
                        if peekline['action'] != 'add':
                            while peekline['action'] == 'del':
                                peekline = next(lineiter)
                            continue
                        # found an add - make sure it is the only one
                        addline = peekline
                        try:
                            peekline = next(lineiter)
                        except StopIteration:
                            # add was last line - ok
                            _highlight_inline_diff(delline, addline)
                            raise
                        if peekline['action'] != 'add':
                            # there was only one add line - ok
                            _highlight_inline_diff(delline, addline)
                except StopIteration:
                    pass

        return _files

    def stat(self):
        """
        Returns tuple of added, and removed lines for this instance
        """
        return self.adds, self.removes


_escape_re = re.compile(r'(&)|(<)|(>)|(\t)($)?|(\r)|( $)')


def _escaper(diff_line):
    r"""
    Do HTML escaping/markup of a single diff line (excluding first +/- column)

    >>> _escaper('foobar')
    'foobar'
    >>> _escaper('@foo & bar')
    '@foo &amp; bar'
    >>> _escaper('foo < bar')
    'foo &lt; bar'
    >>> _escaper('foo > bar')
    'foo &gt; bar'
    >>> _escaper('<foo>')
    '&lt;foo&gt;'
    >>> _escaper('foo\tbar')
    'foo<u>\t</u>bar'
    >>> _escaper('foo\rbar\r')
    'foo<u class="cr"></u>bar<u class="cr"></u>'
    >>> _escaper('foo\t')
    'foo<u>\t</u><i></i>'
    >>> _escaper('foo ')
    'foo <i></i>'
    >>> _escaper('foo  ')
    'foo  <i></i>'
    >>> _escaper('')
    ''
    >>> _escaper(' ')
    ' <i></i>'
    >>> _escaper('\t')
    '<u>\t</u><i></i>'
    >>> _escaper('\t  ')
    '<u>\t</u>  <i></i>'
    >>> _escaper('  \t')
    '  <u>\t</u><i></i>'
    >>> _escaper('\t\t  ')
    '<u>\t</u><u>\t</u>  <i></i>'
    >>> _escaper('  \t\t')
    '  <u>\t</u><u>\t</u><i></i>'
    >>> _escaper('foo&bar<baz>  ')
    'foo&amp;bar&lt;baz&gt;  <i></i>'
    """

    def substitute(m):
        groups = m.groups()
        if groups[0]:
            return '&amp;'
        if groups[1]:
            return '&lt;'
        if groups[2]:
            return '&gt;'
        if groups[3]:
            if groups[4] is not None:  # end of line
                return '<u>\t</u><i></i>'
            return '<u>\t</u>'
        if groups[5]:
            return '<u class="cr"></u>'
        if groups[6]:
            return ' <i></i>'
        assert False

    return _escape_re.sub(substitute, diff_line)


_git_header_re = re.compile(br"""
    ^diff[ ]--git[ ](?P<a_path_quote>"?)a/(?P<a_path>.+?)(?P=a_path_quote)[ ](?P<b_path_quote>"?)b/(?P<b_path>.+?)(?P=a_path_quote)\n
    (?:^old[ ]mode[ ](?P<old_mode>\d+)\n
       ^new[ ]mode[ ](?P<new_mode>\d+)(?:\n|$))?
    (?:^similarity[ ]index[ ](?P<similarity_index>\d+)%\n
       ^rename[ ]from[ ](?P<rename_from>.+)\n
       ^rename[ ]to[ ](?P<rename_to>.+)(?:\n|$))?
    (?:^new[ ]file[ ]mode[ ](?P<new_file_mode>.+)(?:\n|$))?
    (?:^deleted[ ]file[ ]mode[ ](?P<deleted_file_mode>.+)(?:\n|$))?
    (?:^index[ ](?P<a_blob_id>[0-9A-Fa-f]+)
        \.\.(?P<b_blob_id>[0-9A-Fa-f]+)[ ]?(?P<b_mode>.+)?(?:\n|$))?
    (?:^(?P<bin_patch>GIT[ ]binary[ ]patch)(?:\n|$))?
    (?:^---[ ](?P<a_file_quote>"?)(a/(?P<a_file>.+?)(?P=a_file_quote)|/dev/null)\t?(?:\n|$))?
    (?:^\+\+\+[ ](?P<b_file_quote>"?)(b/(?P<b_file>.+?)(?P=b_file_quote)|/dev/null)\t?(?:\n|$))?
""", re.VERBOSE | re.MULTILINE)


_hg_header_re = re.compile(br"""
    ^diff[ ]--git[ ]a/(?P<a_path>.+?)[ ]b/(?P<b_path>.+?)\n
    (?:^old[ ]mode[ ](?P<old_mode>\d+)\n
       ^new[ ]mode[ ](?P<new_mode>\d+)(?:\n|$))?
    (?:^similarity[ ]index[ ](?P<similarity_index>\d+)%(?:\n|$))?
    (?:^rename[ ]from[ ](?P<rename_from>.+)\n
       ^rename[ ]to[ ](?P<rename_to>.+)(?:\n|$))?
    (?:^copy[ ]from[ ](?P<copy_from>.+)\n
       ^copy[ ]to[ ](?P<copy_to>.+)(?:\n|$))?
    (?:^new[ ]file[ ]mode[ ](?P<new_file_mode>.+)(?:\n|$))?
    (?:^deleted[ ]file[ ]mode[ ](?P<deleted_file_mode>.+)(?:\n|$))?
    (?:^index[ ](?P<a_blob_id>[0-9A-Fa-f]+)
        \.\.(?P<b_blob_id>[0-9A-Fa-f]+)[ ]?(?P<b_mode>.+)?(?:\n|$))?
    (?:^(?P<bin_patch>GIT[ ]binary[ ]patch)(?:\n|$))?
    (?:^---[ ](a/(?P<a_file>.+?)|/dev/null)\t?(?:\n|$))?
    (?:^\+\+\+[ ](b/(?P<b_file>.+?)|/dev/null)\t?(?:\n|$))?
""", re.VERBOSE | re.MULTILINE)


_header_next_check = re.compile(br'''(?!@)(?!literal )(?!delta )''')


_git_bs_escape_re = re.compile(r'\\(?:([^0-9])|([0-9]{3}))')


_git_bs_escape_dict = {'\\': '\\', '"': '"', 'r': '\r', 'n': '\n', 't': '\t'}


def _git_bs_unescape_m(m):
    c = m.group(1)
    if c is not None:
        return _git_bs_escape_dict.get(c) or ('\\' + c)
    return chr(int(m.group(2), 8))


def _get_header(vcs, diff_chunk):
    """
    Parses a Git diff for a single file (header and chunks) and returns a tuple with:

    1. A dict with meta info:

        a_path, b_path, similarity_index, rename_from, rename_to,
        old_mode, new_mode, new_file_mode, deleted_file_mode,
        a_blob_id, b_blob_id, b_mode, a_file, b_file

    2. An iterator yielding lines with simple HTML markup.
    """
    match = None
    if vcs == 'git':
        match = _git_header_re.match(diff_chunk)
    elif vcs == 'hg':
        match = _hg_header_re.match(diff_chunk)
    if match is None:
        raise Exception('diff not recognized as valid %s diff: %r' % (vcs, safe_str(bytes(diff_chunk[:1000]))))
    meta_info = {k: None if v is None else safe_str(v) for k, v in match.groupdict().items()}
    if vcs == 'git':
        for k in ['a_path', 'b_path', 'a_file', 'b_file']:
            v = meta_info.get(k)
            if v:
                meta_info[k] = _git_bs_escape_re.sub(_git_bs_unescape_m, v)
    rest = diff_chunk[match.end():]
    if rest:
        if _header_next_check.match(rest):
            raise Exception('cannot parse %s diff header: %r followed by %r' % (vcs, safe_str(bytes(diff_chunk[:match.end()])), safe_str(bytes(rest[:1000]))))
        if rest[-1:] != b'\n':
            # The diff will generally already have trailing \n (and be a memoryview). It might also be huge so we don't want to allocate it twice. But in this very rare case, we don't care.
            rest = bytes(rest) + b'\n'
    diff_lines = (safe_str(m.group(1)) for m in re.finditer(br'(.*)\n', rest))
    return meta_info, diff_lines


_chunk_re = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)')
_newline_marker = re.compile(r'^\\ No newline at end of file')


def _parse_lines(diff_lines):
    """
    Given an iterator of diff body lines, parse them and return a dict per
    line and added/removed totals.
    """
    added = deleted = 0
    old_line = old_end = new_line = new_end = None

    chunks = []
    try:
        line = next(diff_lines)

        while True:
            lines = []
            chunks.append(lines)

            match = _chunk_re.match(line)

            if not match:
                raise Exception('error parsing diff @@ line %r' % line)

            gr = match.groups()
            (old_line, old_end,
             new_line, new_end) = [int(x or 1) for x in gr[:-1]]
            old_line -= 1
            new_line -= 1

            old_end += old_line
            new_end += new_line

            # include '@@' line if it gives a line number hint or separate chunks - not if the chunk starts at start of file like '@@ -1,7 +1,7 @@'
            if int(gr[0]) > 1:
                lines.append({
                    'old_lineno': '',
                    'new_lineno': '',
                    'action':     'context',
                    'line':       line,
                })

            line = next(diff_lines)

            while old_line < old_end or new_line < new_end:
                if not line:
                    raise Exception('error parsing diff - empty line at -%s+%s' % (old_line, new_line))

                affects_old = affects_new = False

                command = line[0]
                if command == '+':
                    affects_new = True
                    action = 'add'
                    added += 1
                elif command == '-':
                    affects_old = True
                    action = 'del'
                    deleted += 1
                elif command == ' ':
                    affects_old = affects_new = True
                    action = 'unmod'
                else:
                    raise Exception('error parsing diff - unknown command in line %r at -%s+%s' % (line, old_line, new_line))

                old_line += affects_old
                new_line += affects_new
                lines.append({
                    'old_lineno':   affects_old and old_line or '',
                    'new_lineno':   affects_new and new_line or '',
                    'action':       action,
                    'line':         line[1:],
                })

                line = next(diff_lines)

                if _newline_marker.match(line):
                    # we need to append to lines, since this is not
                    # counted in the line specs of diff
                    lines.append({
                        'old_lineno':   '',
                        'new_lineno':   '',
                        'action':       'context',
                        'line':         line,
                    })
                    line = next(diff_lines)
            if old_line > old_end:
                raise Exception('error parsing diff - more than %s "-" lines at -%s+%s' % (old_end, old_line, new_line))
            if new_line > new_end:
                raise Exception('error parsing diff - more than %s "+" lines at -%s+%s' % (new_end, old_line, new_line))
    except StopIteration:
        pass
    if old_line != old_end or new_line != new_end:
        raise Exception('diff processing broken when old %s<>%s or new %s<>%s line %r' % (old_line, old_end, new_line, new_end, line))

    return chunks, added, deleted

# Used for inline highlighter word split, must match the substitutions in _escaper
_token_re = re.compile(r'()(&amp;|&lt;|&gt;|<u>\t</u>|<u class="cr"></u>| <i></i>|\W+?)')


def _highlight_inline_diff(old, new):
    """
    Highlight simple add/remove in two lines given as info dicts. They are
    modified in place and given markup with <del>/<ins>.
    """
    assert old['action'] == 'del'
    assert new['action'] == 'add'

    oldwords = _token_re.split(old['line'])
    newwords = _token_re.split(new['line'])
    sequence = difflib.SequenceMatcher(None, oldwords, newwords)

    oldfragments, newfragments = [], []
    for tag, i1, i2, j1, j2 in sequence.get_opcodes():
        oldfrag = ''.join(oldwords[i1:i2])
        newfrag = ''.join(newwords[j1:j2])
        if tag != 'equal':
            if oldfrag:
                oldfrag = '<del>%s</del>' % oldfrag
            if newfrag:
                newfrag = '<ins>%s</ins>' % newfrag
        oldfragments.append(oldfrag)
        newfragments.append(newfrag)

    old['line'] = "".join(oldfragments)
    new['line'] = "".join(newfragments)
