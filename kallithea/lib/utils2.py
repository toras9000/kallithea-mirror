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
kallithea.lib.utils2
~~~~~~~~~~~~~~~~~~~~

Some simple helper functions.
Note: all these functions should be independent of Kallithea classes, i.e.
models, controllers, etc.  to prevent import cycles.

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Jan 5, 2011
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import binascii
import datetime
import hashlib
import json
import logging
import os
import re
import string
import sys
import time
import urllib.parse
from distutils.version import StrictVersion

import bcrypt
import urlobject
from sqlalchemy.engine import url as sa_url
from sqlalchemy.exc import ArgumentError
from tg import tmpl_context
from tg.support.converters import asbool, aslist
from webhelpers2.text import collapse, remove_formatting, strip_tags

import kallithea
from kallithea.lib import webutils
from kallithea.lib.vcs.backends.base import BaseRepository, EmptyChangeset
from kallithea.lib.vcs.backends.git.repository import GitRepository
from kallithea.lib.vcs.conf import settings
from kallithea.lib.vcs.exceptions import RepositoryError
from kallithea.lib.vcs.utils import ascii_bytes, ascii_str, safe_bytes, safe_str  # re-export
from kallithea.lib.vcs.utils.lazy import LazyProperty


try:
    import pwd
except ImportError:
    pass


log = logging.getLogger(__name__)


# mute pyflakes "imported but unused"
assert asbool
assert aslist
assert ascii_bytes
assert ascii_str
assert safe_bytes
assert safe_str
assert LazyProperty


# get current umask value without changing it
umask = os.umask(0)
os.umask(umask)


def convert_line_endings(line, mode):
    """
    Converts a given line  "line end" according to given mode

    Available modes are::
        0 - Unix
        1 - Mac
        2 - DOS

    :param line: given line to convert
    :param mode: mode to convert to
    :rtype: str
    :return: converted line according to mode
    """
    if mode == 0:
        line = line.replace('\r\n', '\n')
        line = line.replace('\r', '\n')
    elif mode == 1:
        line = line.replace('\r\n', '\r')
        line = line.replace('\n', '\r')
    elif mode == 2:
        line = re.sub("\r(?!\n)|(?<!\r)\n", "\r\n", line)
    return line


def detect_mode(line, default):
    """
    Detects line break for given line, if line break couldn't be found
    given default value is returned

    :param line: str line
    :param default: default
    :rtype: int
    :return: value of line end on of 0 - Unix, 1 - Mac, 2 - DOS
    """
    if line.endswith('\r\n'):
        return 2
    elif line.endswith('\n'):
        return 0
    elif line.endswith('\r'):
        return 1
    else:
        return default


def generate_api_key():
    """
    Generates a random (presumably unique) API key.

    This value is used in URLs and "Bearer" HTTP Authorization headers,
    which in practice means it should only contain URL-safe characters
    (RFC 3986):

        unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    """
    # Hexadecimal certainly qualifies as URL-safe.
    return ascii_str(binascii.hexlify(os.urandom(20)))


def safe_int(val, default=None):
    """
    Returns int() of val if val is not convertable to int use default
    instead

    :param val:
    :param default:
    """
    try:
        val = int(val)
    except (ValueError, TypeError):
        val = default
    return val


def remove_suffix(s, suffix):
    if s.endswith(suffix):
        s = s[:-1 * len(suffix)]
    return s


def remove_prefix(s, prefix):
    if s.startswith(prefix):
        s = s[len(prefix):]
    return s


def uri_filter(uri):
    """
    Removes user:password from given url string

    :param uri:
    :rtype: str
    :returns: filtered list of strings
    """
    if not uri:
        return []

    proto = ''

    for pat in ('https://', 'http://', 'git://'):
        if uri.startswith(pat):
            uri = uri[len(pat):]
            proto = pat
            break

    # remove passwords and username
    uri = uri[uri.find('@') + 1:]

    # get the port
    cred_pos = uri.find(':')
    if cred_pos == -1:
        host, port = uri, None
    else:
        host, port = uri[:cred_pos], uri[cred_pos + 1:]

    return [_f for _f in [proto, host, port] if _f]


def credentials_filter(uri):
    """
    Returns a url with removed credentials

    :param uri:
    """

    uri = uri_filter(uri)
    # check if we have port
    if len(uri) > 2 and uri[2]:
        uri[2] = ':' + uri[2]

    return ''.join(uri)


def get_clone_url(clone_uri_tmpl, prefix_url, repo_name, repo_id, username=None):
    parsed_url = urlobject.URLObject(prefix_url)
    prefix = urllib.parse.unquote(parsed_url.path.rstrip('/'))
    try:
        system_user = pwd.getpwuid(os.getuid()).pw_name
    except NameError: # TODO: support all systems - especially Windows
        system_user = 'kallithea' # hardcoded default value ...
    args = {
        'scheme': parsed_url.scheme,
        'user': urllib.parse.quote(username or ''),
        'netloc': parsed_url.netloc + prefix,  # like "hostname:port/prefix" (with optional ":port" and "/prefix")
        'prefix': prefix, # undocumented, empty or starting with /
        'repo': repo_name,
        'repoid': str(repo_id),
        'system_user': system_user,
        'hostname': parsed_url.hostname,
    }
    url = re.sub('{([^{}]+)}', lambda m: args.get(m.group(1), m.group(0)), clone_uri_tmpl)

    # remove leading @ sign if it's present. Case of empty user
    url_obj = urlobject.URLObject(url)
    if not url_obj.username:
        url_obj = url_obj.with_username(None)

    return str(url_obj)


def short_ref_name(ref_type, ref_name):
    """Return short description of PR ref - revs will be truncated"""
    if ref_type == 'rev':
        return ref_name[:12]
    return ref_name


def link_to_ref(repo_name, ref_type, ref_name, rev=None):
    """
    Return full markup for a PR ref to changeset_home for a changeset.
    If ref_type is 'branch', it will link to changelog.
    ref_name is shortened if ref_type is 'rev'.
    if rev is specified, show it too, explicitly linking to that revision.
    """
    txt = short_ref_name(ref_type, ref_name)
    if ref_type == 'branch':
        u = webutils.url('changelog_home', repo_name=repo_name, branch=ref_name)
    else:
        u = webutils.url('changeset_home', repo_name=repo_name, revision=ref_name)
    l = webutils.link_to(repo_name + '#' + txt, u)
    if rev and ref_type != 'rev':
        l = webutils.literal('%s (%s)' % (l, webutils.link_to(rev[:12], webutils.url('changeset_home', repo_name=repo_name, revision=rev))))
    return l


def get_changeset_safe(repo, rev):
    """
    Safe version of get_changeset if this changeset doesn't exists for a
    repo it returns a Dummy one instead

    :param repo:
    :param rev:
    """
    if not isinstance(repo, BaseRepository):
        raise Exception('You must pass an Repository '
                        'object as first argument got %s' % type(repo))

    try:
        cs = repo.get_changeset(rev)
    except (RepositoryError, LookupError):
        cs = EmptyChangeset(requested_revision=rev)
    return cs


def datetime_to_time(dt):
    if dt:
        return time.mktime(dt.timetuple())


def time_to_datetime(tm):
    if tm:
        if isinstance(tm, str):
            try:
                tm = float(tm)
            except ValueError:
                return
        return datetime.datetime.fromtimestamp(tm)


class AttributeDict(dict):
    def __getattr__(self, attr):
        return self.get(attr, None)
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def obfuscate_url_pw(engine):
    try:
        _url = sa_url.make_url(engine or '')
    except ArgumentError:
        return engine
    if _url.password:
        _url.password = 'XXXXX'
    return str(_url)


class HookEnvironmentError(Exception): pass


def get_hook_environment():
    """
    Get hook context by deserializing the global KALLITHEA_EXTRAS environment
    variable.

    Called early in Git out-of-process hooks to get .ini config path so the
    basic environment can be configured properly. Also used in all hooks to get
    information about the action that triggered it.
    """

    try:
        kallithea_extras = os.environ['KALLITHEA_EXTRAS']
    except KeyError:
        raise HookEnvironmentError("Environment variable KALLITHEA_EXTRAS not found")

    extras = json.loads(kallithea_extras)
    for k in ['username', 'repository', 'scm', 'action', 'ip', 'config']:
        try:
            extras[k]
        except KeyError:
            raise HookEnvironmentError('Missing key %s in KALLITHEA_EXTRAS %s' % (k, extras))

    return AttributeDict(extras)


def set_hook_environment(username, ip_addr, repo_name, repo_alias, action=None):
    """Prepare global context for running hooks by serializing data in the
    global KALLITHEA_EXTRAS environment variable.

    Most importantly, this allow Git hooks to do proper logging and updating of
    caches after pushes.

    Must always be called before anything with hooks are invoked.
    """
    extras = {
        'ip': ip_addr, # used in action_logger
        'username': username,
        'action': action or 'push_local', # used in process_pushed_raw_ids action_logger
        'repository': repo_name,
        'scm': repo_alias,
        'config': kallithea.CONFIG['__file__'], # used by git hook to read config
    }
    os.environ['KALLITHEA_EXTRAS'] = json.dumps(extras)


def get_current_authuser():
    """
    Gets kallithea user from threadlocal tmpl_context variable if it's
    defined, else returns None.
    """
    try:
        return getattr(tmpl_context, 'authuser', None)
    except TypeError:  # No object (name: context) has been registered for this thread
        return None


def urlreadable(s, _cleanstringsub=re.compile('[^-a-zA-Z0-9./]+').sub):
    return _cleanstringsub('_', s).rstrip('_')


def recursive_replace(str_, replace=' '):
    """
    Recursive replace of given sign to just one instance

    :param str_: given string
    :param replace: char to find and replace multiple instances

    Examples::
    >>> recursive_replace("Mighty---Mighty-Bo--sstones",'-')
    'Mighty-Mighty-Bo-sstones'
    """

    if str_.find(replace * 2) == -1:
        return str_
    else:
        str_ = str_.replace(replace * 2, replace)
        return recursive_replace(str_, replace)


def repo_name_slug(value):
    """
    Return slug of name of repository
    This function is called on each creation/modification
    of repository to prevent bad names in repo
    """

    slug = remove_formatting(value)
    slug = strip_tags(slug)

    for c in r"""`?=[]\;'"<>,/~!@#$%^&*()+{}|: """:
        slug = slug.replace(c, '-')
    slug = recursive_replace(slug, '-')
    slug = collapse(slug, '-')
    return slug


def ask_ok(prompt, retries=4, complaint='Yes or no please!'):
    while True:
        ok = input(prompt)
        if ok in ('y', 'ye', 'yes'):
            return True
        if ok in ('n', 'no', 'nop', 'nope'):
            return False
        retries = retries - 1
        if retries < 0:
            raise IOError
        print(complaint)


class PasswordGenerator(object):
    """
    This is a simple class for generating password from different sets of
    characters
    usage::

        passwd_gen = PasswordGenerator()
        #print 8-letter password containing only big and small letters
            of alphabet
        passwd_gen.gen_password(8, passwd_gen.ALPHABETS_BIG_SMALL)
    """
    ALPHABETS_NUM = r'''1234567890'''
    ALPHABETS_SMALL = r'''qwertyuiopasdfghjklzxcvbnm'''
    ALPHABETS_BIG = r'''QWERTYUIOPASDFGHJKLZXCVBNM'''
    ALPHABETS_SPECIAL = r'''`-=[]\;',./~!@#$%^&*()_+{}|:"<>?'''
    ALPHABETS_FULL = ALPHABETS_BIG + ALPHABETS_SMALL \
        + ALPHABETS_NUM + ALPHABETS_SPECIAL
    ALPHABETS_ALPHANUM = ALPHABETS_BIG + ALPHABETS_SMALL + ALPHABETS_NUM
    ALPHABETS_BIG_SMALL = ALPHABETS_BIG + ALPHABETS_SMALL
    ALPHABETS_ALPHANUM_BIG = ALPHABETS_BIG + ALPHABETS_NUM
    ALPHABETS_ALPHANUM_SMALL = ALPHABETS_SMALL + ALPHABETS_NUM

    def gen_password(self, length, alphabet=ALPHABETS_FULL):
        assert len(alphabet) <= 256, alphabet
        l = []
        while len(l) < length:
            i = ord(os.urandom(1))
            if i < len(alphabet):
                l.append(alphabet[i])
        return ''.join(l)


def get_crypt_password(password):
    """
    Cryptographic function used for bcrypt password hashing.

    :param password: password to hash
    """
    return ascii_str(bcrypt.hashpw(safe_bytes(password), bcrypt.gensalt(10)))


def check_password(password, hashed):
    """
    Checks password match the hashed value using bcrypt.
    Remains backwards compatible and accept plain sha256 hashes which used to
    be used on Windows.

    :param password: password
    :param hashed: password in hashed form
    """
    # sha256 hashes will always be 64 hex chars
    # bcrypt hashes will always contain $ (and be shorter)
    if len(hashed) == 64 and all(x in string.hexdigits for x in hashed):
        return hashlib.sha256(password).hexdigest() == hashed
    try:
        return bcrypt.checkpw(safe_bytes(password), ascii_bytes(hashed))
    except ValueError as e:
        # bcrypt will throw ValueError 'Invalid hashed_password salt' on all password errors
        log.error('error from bcrypt checking password: %s', e)
        return False
    log.error('check_password failed - no method found for hash length %s', len(hashed))
    return False


git_req_ver = StrictVersion('1.7.4')

def check_git_version():
    """
    Checks what version of git is installed on the system, and raise a system exit
    if it's too old for Kallithea to work properly.
    """
    if 'git' not in kallithea.BACKENDS:
        return None

    if not settings.GIT_EXECUTABLE_PATH:
        log.warning('No git executable configured - check "git_path" in the ini file.')
        return None

    try:
        stdout, stderr = GitRepository._run_git_command(['--version'])
    except RepositoryError as e:
        # message will already have been logged as error
        log.warning('No working git executable found - check "git_path" in the ini file.')
        return None

    if stderr:
        log.warning('Error/stderr from "%s --version":\n%s', settings.GIT_EXECUTABLE_PATH, safe_str(stderr))

    if not stdout:
        log.warning('No working git executable found - check "git_path" in the ini file.')
        return None

    output = safe_str(stdout).strip()
    m = re.search(r"\d+.\d+.\d+", output)
    if m:
        ver = StrictVersion(m.group(0))
        log.debug('Git executable: "%s", version %s (parsed from: "%s")',
                  settings.GIT_EXECUTABLE_PATH, ver, output)
        if ver < git_req_ver:
            log.error('Kallithea detected %s version %s, which is too old '
                      'for the system to function properly. '
                      'Please upgrade to version %s or later. '
                      'If you strictly need Mercurial repositories, you can '
                      'clear the "git_path" setting in the ini file.',
                      settings.GIT_EXECUTABLE_PATH, ver, git_req_ver)
            log.error("Terminating ...")
            sys.exit(1)
    else:
        ver = StrictVersion('0.0.0')
        log.warning('Error finding version number in "%s --version" stdout:\n%s',
                    settings.GIT_EXECUTABLE_PATH, output)

    return ver
