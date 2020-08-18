"""Kallithea Git hook

This hook is installed and maintained by Kallithea. It will be overwritten
by Kallithea - don't customize it manually!

When Kallithea invokes Git, the KALLITHEA_EXTRAS environment variable will
contain additional info like the Kallithea instance and user info that this
hook will use.
"""

import os
import subprocess
import sys

import kallithea.bin.vcs_hooks


# Set output mode on windows to binary for stderr.
# This prevents python (or the windows console) from replacing \n with \r\n.
# Git doesn't display remote output lines that contain \r,
# and therefore without this modification git would display empty lines
# instead of the exception output.
if sys.platform == "win32":
    import msvcrt
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)  # pytype: disable=module-attr

KALLITHEA_HOOK_VER = '_TMPL_'
os.environ['KALLITHEA_HOOK_VER'] = KALLITHEA_HOOK_VER


def main():
    repo_path = os.path.abspath('.')
    git_stdin_lines = sys.stdin.readlines()
    status = kallithea.bin.vcs_hooks.post_receive(repo_path, git_stdin_lines)

    custom_hook = os.path.join(repo_path, 'hooks', 'post-receive-custom')
    custom_status = None
    if os.access(custom_hook, os.X_OK):
        result = subprocess.run([custom_hook], input=''.join(git_stdin_lines), universal_newlines=True)
        custom_status = result.returncode

    sys.exit(status or custom_status)


if __name__ == '__main__':
    main()
