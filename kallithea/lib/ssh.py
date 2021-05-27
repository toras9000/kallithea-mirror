# -*- coding: utf-8 -*-
"""
    kallithea.lib.ssh
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :created_on: Dec 10, 2012
    :author: ir4y
    :copyright: (C) 2012 Ilya Beda <ir4y.ix@gmail.com>
    :license: GPLv3, see COPYING for more details.
"""
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

import base64
import binascii
import logging
import re
import struct

from tg.i18n import ugettext as _

from kallithea.lib.utils2 import ascii_str


log = logging.getLogger(__name__)


class SshKeyParseError(Exception):
    """Exception raised by parse_pub_key"""

algorithm_types = {  # mapping name to number of data strings in key
    # https://tools.ietf.org/html/rfc4253#section-6.6
    'ssh-rsa': 2,  # e, n
    'ssh-dss': 4,  # p, q, g, y
    # https://tools.ietf.org/html/rfc8709
    'ssh-ed25519': 1,
    'ssh-ed448': 1,
}

def parse_pub_key(ssh_key):
    r"""Parse SSH public key string, raise SshKeyParseError or return decoded keytype, data and comment

    >>> getfixture('doctest_mock_ugettext')
    >>> parse_pub_key('')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: SSH key is missing
    >>> parse_pub_key('''AAAAB3NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - it must have both a key type and a base64 part, like 'ssh-rsa ASRNeaZu4FA...xlJp='
    >>> parse_pub_key('''abc AAAAB3NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - it must start with key type 'ssh-rsa', 'ssh-dss', 'ssh-ed448', or 'ssh-ed25519'
    >>> parse_pub_key('''ssh-rsa  AAAAB3NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - base64 part 'AAAAB3NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ' seems truncated (it can't be decoded)
    >>> parse_pub_key('''ssh-rsa  AAAAB2NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ==''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - base64 part 'AAAAB2NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ==' seems truncated (it contains a partial string length)
    >>> parse_pub_key('''ssh-rsa AAAAB2NzaC1yc2EAAAANVGhpcyBpcyE=''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - base64 part 'AAAAB2NzaC1yc2EAAAANVGhpcyBpcyE=' seems truncated (it is too short for declared string length 13)
    >>> parse_pub_key('''ssh-rsa AAAAB2NzaC1yc2EAAAANVGhpcyBpcyBmYWtlIQ==''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - base64 part 'AAAAB2NzaC1yc2EAAAANVGhpcyBpcyBmYWtlIQ==' seems truncated (it contains too few strings for a ssh-rsa key)
    >>> parse_pub_key('''ssh-rsa AAAAB2NzaC1yc2EAAAANVGhpcyBpcyBmYWtlIQAAAANieWU=''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - it is a ssh-rsa key but the base64 part contains 'csh-rsa'
    >>> parse_pub_key('''ssh-rsa  AAAAB3NzaC1yc2EAAAA'LVGhpcyBpcyBmYWtlIQ''')
    Traceback (most recent call last):
    ...
    kallithea.lib.ssh.SshKeyParseError: Invalid SSH key - unexpected characters in base64 part "AAAAB3NzaC1yc2EAAAA'LVGhpcyBpcyBmYWtlIQ"
    >>> parse_pub_key(''' ssh-rsa  AAAAB3NzaC1yc2EAAAANVGhpcyBpcyBmYWtlIQAAAANieWU= and a comment
    ... ''')
    ('ssh-rsa', b'\x00\x00\x00\x07ssh-rsa\x00\x00\x00\rThis is fake!\x00\x00\x00\x03bye', 'and a comment\n')
    >>> parse_pub_key('''ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP1NA2kBQIKe74afUXmIWD9ByDYQJqUwW44Y4gJOBRuo''')
    ('ssh-ed25519', b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \xfdM\x03i\x01@\x82\x9e\xef\x86\x9fQy\x88X?A\xc86\x10&\xa50[\x8e\x18\xe2\x02N\x05\x1b\xa8', '')
    """
    if not ssh_key:
        raise SshKeyParseError(_("SSH key is missing"))

    parts = ssh_key.split(None, 2)
    if len(parts) < 2:
        raise SshKeyParseError(_("Invalid SSH key - it must have both a key type and a base64 part, like 'ssh-rsa ASRNeaZu4FA...xlJp='"))

    keytype, keyvalue, comment = (parts + [''])[:3]
    keytype_data_size = algorithm_types.get(keytype)
    if keytype_data_size is None:
        raise SshKeyParseError(_("Invalid SSH key - it must start with key type 'ssh-rsa', 'ssh-dss', 'ssh-ed448', or 'ssh-ed25519'"))

    if re.search(r'[^a-zA-Z0-9+/=]', keyvalue):  # make sure b64decode doesn't stop at the first invalid character and skip the rest
        raise SshKeyParseError(_("Invalid SSH key - unexpected characters in base64 part %r") % keyvalue)

    try:
        key_bytes = base64.b64decode(keyvalue)
    except binascii.Error:  # Must be caused by truncation - either "Invalid padding" or "Invalid base64-encoded string: number of data characters (x) cannot be 1 more than a multiple of 4"
        raise SshKeyParseError(_("Invalid SSH key - base64 part %r seems truncated (it can't be decoded)") % keyvalue)

    # Check key internals to make sure the key wasn't truncated in a way that base64 can decode:
    # Parse and verify key according to https://tools.ietf.org/html/rfc4253#section-6.6
    strings = []
    offset = 0
    while offset < len(key_bytes):
        try:
            string_length, = struct.unpack_from('!I', key_bytes, offset)
        except struct.error:  # unpack_from requires a buffer of at least 283 bytes for unpacking 4 bytes at offset 279 (actual buffer size is 280)
            raise SshKeyParseError(_("Invalid SSH key - base64 part %r seems truncated (it contains a partial string length)") % keyvalue)
        offset += 4
        string = key_bytes[offset:offset + string_length]
        if len(string) != string_length:
            raise SshKeyParseError(_("Invalid SSH key - base64 part %r seems truncated (it is too short for declared string length %s)") % (keyvalue, string_length))
        strings.append(string)
        offset += string_length
    if len(strings) != keytype_data_size + 1:
        raise SshKeyParseError(_("Invalid SSH key - base64 part %r seems truncated (it contains too few strings for a %s key)") % (keyvalue, keytype))
    if ascii_str(strings[0]) != keytype:
        raise SshKeyParseError(_("Invalid SSH key - it is a %s key but the base64 part contains %r") % (keytype, ascii_str(strings[0])))

    return keytype, key_bytes, comment


SSH_OPTIONS = 'no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding'


def _safe_check(s, rec = re.compile('^[a-zA-Z0-9+/]+={0,2}$')):
    """Return true if s really has the right content for base64 encoding and only contains safe characters
    >>> _safe_check('asdf')
    True
    >>> _safe_check('as df')
    False
    >>> _safe_check('AAAAB3NzaC1yc2EAAAALVGhpcyBpcyBmYWtlIQ==')
    True
    """
    return rec.match(s) is not None


def authorized_keys_line(kallithea_cli_path, config_file, key):
    r"""
    Return a line as it would appear in .authorized_keys

    >>> getfixture('doctest_mock_ugettext')
    >>> from kallithea.model import db
    >>> user = db.User(user_id=7, username='uu')
    >>> key = db.UserSshKeys(user_ssh_key_id=17, user=user, description='test key')
    >>> key.public_key='''ssh-rsa  AAAAB3NzaC1yc2EAAAANVGhpcyBpcyBmYWtlIQAAAANieWU= and a comment'''
    >>> authorized_keys_line('/srv/kallithea/venv/bin/kallithea-cli', '/srv/kallithea/my.ini', key)
    'no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding,command="/srv/kallithea/venv/bin/kallithea-cli ssh-serve -c /srv/kallithea/my.ini 7 17" ssh-rsa AAAAB3NzaC1yc2EAAAANVGhpcyBpcyBmYWtlIQAAAANieWU=\n'
    """
    try:
        keytype, key_bytes, comment = parse_pub_key(key.public_key)
    except SshKeyParseError:
        return '# Invalid Kallithea SSH key: %s %s\n' % (key.user.user_id, key.user_ssh_key_id)
    base64_key = ascii_str(base64.b64encode(key_bytes))
    assert '\n' not in base64_key
    if not _safe_check(base64_key):
        return '# Invalid Kallithea SSH key - bad base64 encoding: %s %s\n' % (key.user.user_id, key.user_ssh_key_id)
    return '%s,command="%s ssh-serve -c %s %s %s" %s %s\n' % (
        SSH_OPTIONS, kallithea_cli_path, config_file,
        key.user.user_id, key.user_ssh_key_id,
        keytype, base64_key)
