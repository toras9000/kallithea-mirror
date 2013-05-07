from __future__ import with_statement
import os
import unittest
from rhodecode.tests import *
from rhodecode.lib.diffs import DiffProcessor, NEW_FILENODE, DEL_FILENODE, \
    MOD_FILENODE, RENAMED_FILENODE, CHMOD_FILENODE, BIN_FILENODE

dn = os.path.dirname
FIXTURES = os.path.join(dn(dn(os.path.abspath(__file__))), 'fixtures')

DIFF_FIXTURES = {
    'hg_diff_add_single_binary_file.diff': [
        ('US Warszawa.jpg', 'A',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {NEW_FILENODE: 'new file 100755',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_mod_single_binary_file.diff': [
        ('US Warszawa.jpg', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {MOD_FILENODE: 'modified file',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],

    'hg_diff_mod_single_file_and_rename_and_chmod.diff': [
        ('README', 'M',
         {'added': 3,
          'deleted': 0,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file',
                  RENAMED_FILENODE: 'file renamed from README.rst to README',
                  CHMOD_FILENODE: 'modified file chmod 100755 => 100644'}}),
    ],
    'hg_diff_rename_and_chmod_file.diff': [
        ('README', 'M',
         {'added': 3,
          'deleted': 0,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_del_single_binary_file.diff': [
        ('US Warszawa.jpg', 'D',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {DEL_FILENODE: 'deleted file',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_chmod_and_mod_single_binary_file.diff': [
        ('gravatar.png', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100644 => 100755',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_chmod.diff': [
        ('file', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100755 => 100644'}}),
    ],
    'hg_diff_rename_file.diff': [
        ('file_renamed', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {RENAMED_FILENODE: 'file renamed from file to file_renamed'}}),
    ],
    'hg_diff_rename_and_chmod_file.diff': [
        ('README', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100644 => 100755',
                  RENAMED_FILENODE: 'file renamed from README.rst to README'}}),
    ],
    'hg_diff_binary_and_normal.diff': [
        ('img/baseline-10px.png', 'A',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {NEW_FILENODE: 'new file 100644',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('js/jquery/hashgrid.js', 'A',
         {'added': 340,
          'deleted': 0,
          'binary': False,
          'ops': {NEW_FILENODE: 'new file 100755'}}),
        ('index.html', 'M',
         {'added': 3,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('less/docs.less', 'M',
         {'added': 34,
          'deleted': 0,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('less/scaffolding.less', 'M',
         {'added': 1,
          'deleted': 3,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('readme.markdown', 'M',
         {'added': 1,
          'deleted': 10,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('img/baseline-20px.png', 'D',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {DEL_FILENODE: 'deleted file',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('js/global.js', 'D',
         {'added': 0,
          'deleted': 75,
          'binary': False,
          'ops': {DEL_FILENODE: 'deleted file'}})
    ],
    'git_diff_chmod.diff': [
        ('work-horus.xls', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100644 => 100755'}})
    ],
    'git_diff_rename_file.diff': [
        ('file.xls', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {RENAMED_FILENODE: 'file renamed from work-horus.xls to file.xls'}})
    ],
    'git_diff_mod_single_binary_file.diff': [
        ('US Warszawa.jpg', 'M',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {MOD_FILENODE: 'modified file',
                  BIN_FILENODE: 'binary diff not shown'}})
    ],
    'git_diff_binary_and_normal.diff': [
        ('img/baseline-10px.png', 'A',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {NEW_FILENODE: 'new file 100644',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('js/jquery/hashgrid.js', 'A',
         {'added': 340,
          'deleted': 0,
          'binary': False,
          'ops': {NEW_FILENODE: 'new file 100755'}}),
        ('index.html', 'M',
         {'added': 3,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('less/docs.less', 'M',
         {'added': 34,
          'deleted': 0,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('less/scaffolding.less', 'M',
         {'added': 1,
          'deleted': 3,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('readme.markdown', 'M',
         {'added': 1,
          'deleted': 10,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('img/baseline-20px.png', 'D',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {DEL_FILENODE: 'deleted file',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('js/global.js', 'D',
         {'added': 0,
          'deleted': 75,
          'binary': False,
          'ops': {DEL_FILENODE: 'deleted file'}}),
    ],
    'diff_with_diff_data.diff': [
        ('vcs/backends/base.py', 'M',
         {'added': 18,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/backends/git/repository.py', 'M',
         {'added': 46,
          'deleted': 15,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/backends/hg.py', 'M',
         {'added': 22,
          'deleted': 3,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/tests/test_git.py', 'M',
         {'added': 5,
          'deleted': 5,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/tests/test_repository.py', 'M',
         {'added': 174,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
    ],
#     'large_diff.diff': [
#         ('.hgignore', 'A', {'deleted': 0, 'binary': False, 'added': 3, 'ops': {1: 'new file 100644'}}),
#         ('MANIFEST.in', 'A', {'deleted': 0, 'binary': False, 'added': 3, 'ops': {1: 'new file 100644'}}),
#         ('README.txt', 'A', {'deleted': 0, 'binary': False, 'added': 19, 'ops': {1: 'new file 100644'}}),
#         ('development.ini', 'A', {'deleted': 0, 'binary': False, 'added': 116, 'ops': {1: 'new file 100644'}}),
#         ('docs/index.txt', 'A', {'deleted': 0, 'binary': False, 'added': 19, 'ops': {1: 'new file 100644'}}),
#         ('ez_setup.py', 'A', {'deleted': 0, 'binary': False, 'added': 276, 'ops': {1: 'new file 100644'}}),
#         ('hgapp.py', 'A', {'deleted': 0, 'binary': False, 'added': 26, 'ops': {1: 'new file 100644'}}),
#         ('hgwebdir.config', 'A', {'deleted': 0, 'binary': False, 'added': 21, 'ops': {1: 'new file 100644'}}),
#         ('pylons_app.egg-info/PKG-INFO', 'A', {'deleted': 0, 'binary': False, 'added': 10, 'ops': {1: 'new file 100644'}}),
#         ('pylons_app.egg-info/SOURCES.txt', 'A', {'deleted': 0, 'binary': False, 'added': 33, 'ops': {1: 'new file 100644'}}),
#         ('pylons_app.egg-info/dependency_links.txt', 'A', {'deleted': 0, 'binary': False, 'added': 1, 'ops': {1: 'new file 100644'}}),
#         #TODO:
#     ],

}


class DiffLibTest(unittest.TestCase):

    @parameterized.expand([(x,) for x in DIFF_FIXTURES])
    def test_diff(self, diff_fixture):

        with open(os.path.join(FIXTURES, diff_fixture)) as f:
            diff = f.read()

        diff_proc = DiffProcessor(diff)
        diff_proc_d = diff_proc.prepare()
        data = [(x['filename'], x['operation'], x['stats']) for x in diff_proc_d]
        expected_data = DIFF_FIXTURES[diff_fixture]
        self.assertListEqual(expected_data, data)
