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
kallithea.bin.vcs_hooks
~~~~~~~~~~~~~~~~~~~~~~~

Entry points for Kallithea hooking into Mercurial and Git.

This file was forked by the Kallithea project in July 2014.
Original author and date, and relevant copyright and licensing information is below:
:created_on: Aug 6, 2010
:author: marcink
:copyright: (c) 2013 RhodeCode GmbH, and others.
:license: GPLv3, see LICENSE.md for more details.
"""

import logging
import os
import sys

import mercurial.hg
import mercurial.scmutil
import paste.deploy

import kallithea
import kallithea.config.application
from kallithea.lib import hooks, webutils
from kallithea.lib.utils2 import HookEnvironmentError, ascii_str, get_hook_environment, safe_bytes, safe_str
from kallithea.lib.vcs.backends.base import EmptyChangeset
from kallithea.lib.vcs.utils.helpers import get_scm_size
from kallithea.model import db


log = logging.getLogger(__name__)


def repo_size(ui, repo, hooktype=None, **kwargs):
    """Show size of Mercurial repository.

    Called as Mercurial hook changegroup.kallithea_repo_size after push.
    """
    size_hg, size_root = get_scm_size('.hg', safe_str(repo.root))

    last_cs = repo[len(repo) - 1]

    msg = ('Repository size .hg: %s Checkout: %s Total: %s\n'
           'Last revision is now r%s:%s\n') % (
        webutils.format_byte_size(size_hg),
        webutils.format_byte_size(size_root),
        webutils.format_byte_size(size_hg + size_root),
        last_cs.rev(),
        ascii_str(last_cs.hex())[:12],
    )
    ui.status(safe_bytes(msg))


def update(ui, repo, hooktype=None, **kwargs):
    """Update repo after push. The equivalent to 'hg update' but using the same
    Mercurial as everything else.

    Called as Mercurial hook changegroup.kallithea_update after push.
    """
    try:
        ui.pushbuffer(error=True, subproc=True)
        rev = brev = None
        mercurial.hg.updatetotally(ui, repo, rev, brev)
    finally:
        s = ui.popbuffer()  # usually just "x files updated, x files merged, x files removed, x files unresolved"
        log.info('%s update hook output: %s', safe_str(repo.root), safe_str(s).rstrip())


def pull_action(ui, repo, **kwargs):
    """Logs user pull action

    Called as Mercurial hook outgoing.kallithea_pull_action.
    """
    hooks.log_pull_action()


def push_action(ui, repo, node, node_last, **kwargs):
    """
    Register that changes have been added to the repo - log the action *and* invalidate caches.
    Note: This hook is not only logging, but also the side effect invalidating
    caches! The function should perhaps be renamed.

    Called as Mercurial hook changegroup.kallithea_push_action .

    The pushed changesets is given by the revset 'node:node_last'.
    """
    revs = [ascii_str(repo[r].hex()) for r in mercurial.scmutil.revrange(repo, [b'%s:%s' % (node, node_last)])]
    hooks.process_pushed_raw_ids(revs)


def _git_hook_environment(repo_path):
    """
    Create a light-weight environment for stand-alone scripts and return an UI and the
    db repository.

    Git hooks are executed as subprocess of Git while Kallithea is waiting, and
    they thus need enough info to be able to create an app environment and
    connect to the database.
    """
    extras = get_hook_environment()

    path_to_ini_file = extras['config']
    config = paste.deploy.appconfig('config:' + path_to_ini_file)
    #logging.config.fileConfig(ini_file_path) # Note: we are in a different process - don't use configured logging
    kallithea.config.application.make_app(config.global_conf, **config.local_conf)

    # fix if it's not a bare repo
    if repo_path.endswith(os.sep + '.git'):
        repo_path = repo_path[:-5]

    repo = db.Repository.get_by_full_path(repo_path)
    if not repo:
        raise OSError('Repository %s not found in database' % repo_path)

    return repo


def post_receive(repo_path, git_stdin_lines):
    """Called from Git post-receive hook.
    The returned value is used as hook exit code and must be 0.
    """
    try:
        repo = _git_hook_environment(repo_path)
    except HookEnvironmentError as e:
        sys.stderr.write("Skipping Kallithea Git post-receive hook %r.\nGit was apparently not invoked by Kallithea: %s\n" % (sys.argv[0], e))
        return 0

    # the post push hook should never use the cached instance
    scm_repo = repo.scm_instance_no_cache()

    rev_data = []
    for l in git_stdin_lines:
        old_rev, new_rev, ref = l.strip().split(' ')
        _ref_data = ref.split('/')
        if _ref_data[1] in ['tags', 'heads']:
            rev_data.append({'old_rev': old_rev,
                             'new_rev': new_rev,
                             'ref': ref,
                             'type': _ref_data[1],
                             'name': '/'.join(_ref_data[2:])})

    git_revs = []
    for push_ref in rev_data:
        _type = push_ref['type']
        if _type == 'heads':
            if push_ref['old_rev'] == EmptyChangeset().raw_id:
                # update the symbolic ref if we push new repo
                if scm_repo.is_empty():
                    scm_repo._repo.refs.set_symbolic_ref(
                        b'HEAD',
                        b'refs/heads/%s' % safe_bytes(push_ref['name']))

                # build exclude list without the ref
                cmd = ['for-each-ref', '--format=%(refname)', 'refs/heads/*']
                stdout = scm_repo.run_git_command(cmd)
                ref = push_ref['ref']
                heads = [head for head in stdout.splitlines() if head != ref]
                # now list the git revs while excluding from the list
                cmd = ['log', push_ref['new_rev'], '--reverse', '--pretty=format:%H']
                cmd.append('--not')
                cmd.extend(heads) # empty list is ok
                stdout = scm_repo.run_git_command(cmd)
                git_revs += stdout.splitlines()

            elif push_ref['new_rev'] == EmptyChangeset().raw_id:
                # delete branch case
                git_revs += ['delete_branch=>%s' % push_ref['name']]
            else:
                cmd = ['log', '%(old_rev)s..%(new_rev)s' % push_ref,
                       '--reverse', '--pretty=format:%H']
                stdout = scm_repo.run_git_command(cmd)
                git_revs += stdout.splitlines()

        elif _type == 'tags':
            git_revs += ['tag=>%s' % push_ref['name']]

    hooks.process_pushed_raw_ids(git_revs)

    return 0


# Almost exactly like Mercurial contrib/hg-ssh:
def rejectpush(ui, **kwargs):
    """Mercurial hook to be installed as pretxnopen and prepushkey for read-only repos.
    Return value 1 will make the hook fail and reject the push.
    """
    ex = get_hook_environment()
    ui.warn(safe_bytes("Push access to %r denied\n" % ex.repository))
    return 1
