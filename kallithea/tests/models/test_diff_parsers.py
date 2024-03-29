from kallithea.lib.diffs import BIN_FILENODE, CHMOD_FILENODE, COPIED_FILENODE, DEL_FILENODE, MOD_FILENODE, NEW_FILENODE, RENAMED_FILENODE, DiffProcessor
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


DIFF_FIXTURES = {
    'hg_diff_add_single_binary_file.diff': [
        ('US Warszawa.jpg', 'added',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {NEW_FILENODE: 'new file 100755',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_mod_single_binary_file.diff': [
        ('US Warszawa.jpg', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {MOD_FILENODE: 'modified file',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],

    'hg_diff_mod_single_file_and_rename_and_chmod.diff': [
        ('README', 'renamed',
         {'added': 3,
          'deleted': 0,
          'binary': False,
          'ops': {RENAMED_FILENODE: 'file renamed from README.rst to README',
                  CHMOD_FILENODE: 'modified file chmod 100755 => 100644'}}),
    ],
    'hg_diff_mod_file_and_rename.diff': [
        ('README.rst', 'renamed',
         {'added': 3,
          'deleted': 0,
          'binary': False,
          'ops': {RENAMED_FILENODE: 'file renamed from README to README.rst'}}),
    ],
    'hg_diff_del_single_binary_file.diff': [
        ('US Warszawa.jpg', 'removed',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {DEL_FILENODE: 'deleted file',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_chmod_and_mod_single_binary_file.diff': [
        ('gravatar.png', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100644 => 100755',
                  BIN_FILENODE: 'binary diff not shown'}}),
    ],
    'hg_diff_chmod.diff': [
        ('file', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100755 => 100644'}}),
    ],
    'hg_diff_rename_file.diff': [
        ('file_renamed', 'renamed',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {RENAMED_FILENODE: 'file renamed from file to file_renamed'}}),
    ],
    'hg_diff_rename_and_chmod_file.diff': [
        ('README', 'renamed',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100644 => 100755',
                  RENAMED_FILENODE: 'file renamed from README.rst to README'}}),
    ],
    'hg_diff_binary_and_normal.diff': [
        ('img/baseline-10px.png', 'added',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {NEW_FILENODE: 'new file 100644',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('img/baseline-20px.png', 'removed',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {DEL_FILENODE: 'deleted file',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('index.html', 'modified',
         {'added': 3,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('js/global.js', 'removed',
         {'added': 0,
          'deleted': 75,
          'binary': False,
          'ops': {DEL_FILENODE: 'deleted file'}}),
        ('js/jquery/hashgrid.js', 'added',
         {'added': 340,
          'deleted': 0,
          'binary': False,
          'ops': {NEW_FILENODE: 'new file 100755'}}),
        ('less/docs.less', 'modified',
         {'added': 34,
          'deleted': 0,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('less/scaffolding.less', 'modified',
         {'added': 1,
          'deleted': 3,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('readme.markdown', 'modified',
         {'added': 1,
          'deleted': 10,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
    ],
    'git_diff_chmod.diff': [
        ('work-horus.xls', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {CHMOD_FILENODE: 'modified file chmod 100644 => 100755'}})
    ],
    'git_diff_rename_file.diff': [
        ('file.xls', 'renamed',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {RENAMED_FILENODE: 'file renamed from work-horus.xls to file.xls'}}),
        ('files/var/www/favicon.ico/DEFAULT',
         'renamed',
         {'added': 0,
          'binary': True,
          'deleted': 0,
          'ops': {4: 'file renamed from files/var/www/favicon.ico to files/var/www/favicon.ico/DEFAULT',
                  6: 'modified file chmod 100644 => 100755'}})
    ],
    'git_diff_mod_single_binary_file.diff': [
        ('US Warszawa.jpg', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {MOD_FILENODE: 'modified file',
                  BIN_FILENODE: 'binary diff not shown'}})
    ],
    'git_diff_binary_and_normal.diff': [
        ('img/baseline-10px.png', 'added',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {NEW_FILENODE: 'new file 100644',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('img/baseline-20px.png', 'removed',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {DEL_FILENODE: 'deleted file',
                  BIN_FILENODE: 'binary diff not shown'}}),
        ('index.html', 'modified',
         {'added': 3,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('js/global.js', 'removed',
         {'added': 0,
          'deleted': 75,
          'binary': False,
          'ops': {DEL_FILENODE: 'deleted file'}}),
        ('js/jquery/hashgrid.js', 'added',
         {'added': 340,
          'deleted': 0,
          'binary': False,
          'ops': {NEW_FILENODE: 'new file 100755'}}),
        ('less/docs.less', 'modified',
         {'added': 34,
          'deleted': 0,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('less/scaffolding.less', 'modified',
         {'added': 1,
          'deleted': 3,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('readme.markdown', 'modified',
         {'added': 1,
          'deleted': 10,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
    ],
    'diff_with_diff_data.diff': [
        ('vcs/backends/base.py', 'modified',
         {'added': 18,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/backends/git/repository.py', 'modified',
         {'added': 46,
          'deleted': 15,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/backends/hg.py', 'modified',
         {'added': 22,
          'deleted': 3,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/tests/test_git.py', 'modified',
         {'added': 5,
          'deleted': 5,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
        ('vcs/tests/test_repository.py', 'modified',
         {'added': 174,
          'deleted': 2,
          'binary': False,
          'ops': {MOD_FILENODE: 'modified file'}}),
    ],
    'git_diff_modify_binary_file.diff': [
        ('file.name', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {MOD_FILENODE: 'modified file',
                  BIN_FILENODE: 'binary diff not shown'}})
    ],
    'hg_diff_copy_file.diff': [
        ('file2', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {COPIED_FILENODE: 'file copied from file1 to file2'}}),
    ],
    'hg_diff_copy_and_modify_file.diff': [
        ('file3', 'modified',
         {'added': 1,
          'deleted': 0,
          'binary': False,
          'ops': {COPIED_FILENODE: 'file copied from file2 to file3',
                  MOD_FILENODE: 'modified file'}}),
    ],
    'hg_diff_copy_and_chmod_file.diff': [
        ('file4', 'modified',
         {'added': 0,
          'deleted': 0,
          'binary': True,
          'ops': {COPIED_FILENODE: 'file copied from file3 to file4',
                  CHMOD_FILENODE: 'modified file chmod 100644 => 100755'}}),
    ],
    'hg_diff_copy_chmod_and_edit_file.diff': [
        ('file5', 'modified',
         {'added': 2,
          'deleted': 1,
          'binary': False,
          'ops': {COPIED_FILENODE: 'file copied from file4 to file5',
                  CHMOD_FILENODE: 'modified file chmod 100755 => 100644',
                  MOD_FILENODE: 'modified file'}}),
    ],
    'hg_diff_rename_space_cr.diff': [
        ('oh yes', 'renamed',
         {'added': 3,
          'deleted': 2,
          'binary': False,
          'ops': {RENAMED_FILENODE: 'file renamed from oh no to oh yes'}}),
    ],
    'git_diff_quoting.diff': [
        ('"foo"',
         'added',
         {'added': 1,
          'binary': False,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ("'foo'",
         'added',
         {'added': 1,
          'binary': False,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ("'foo'" '"foo"',
         'added',
         {'added': 1,
          'binary': False,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ('a\r\nb',  # Note: will be parsed correctly, but other parts of Kallithea can't handle it
         'added',
         {'added': 1,
          'binary': False,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ('foo\rfoo',  # Note: will be parsed correctly, but other parts of Kallithea can't handle it
         'added',
        {'added': 0,
         'binary': True,
         'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ('foo bar',
         'added',
         {'added': 1,
          'binary': False,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ('test',
         'added',
         {'added': 1,
          'binary': False,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ('esc\033foo',  # Note: will be parsed and handled correctly, but without good UI
         'added',
         {'added': 0,
          'binary': True,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
        ('tab\tfoo',  # Note: will be parsed and handled correctly, but without good UI
         'added',
         {'added': 0,
          'binary': True,
          'deleted': 0,
          'ops': {1: 'new file 100644'}}),
    ],
}


class TestDiffLib(base.TestController):

    @base.parametrize('diff_fixture', DIFF_FIXTURES)
    def test_diff(self, diff_fixture):
        raw_diff = fixture.load_resource(diff_fixture, strip=False)
        vcs = 'hg'
        if diff_fixture.startswith('git_'):
            vcs = 'git'
        diff_processor = DiffProcessor(raw_diff, vcs=vcs)
        data = [(x['filename'], x['operation'], x['stats']) for x in diff_processor.parsed]
        expected_data = DIFF_FIXTURES[diff_fixture]
        assert expected_data == data

    def test_diff_markup(self):
        raw_diff = fixture.load_resource('markuptest.diff', strip=False)
        diff_processor = DiffProcessor(raw_diff)
        chunks = diff_processor.parsed[0]['chunks']
        assert len(chunks) == 1, chunks
        #from pprint import pprint; pprint(chunks[1])
        l = ['\n']
        for d in chunks[0]:
            l.append('%(action)-7s %(new_lineno)3s %(old_lineno)3s %(line)r\n' % d)
        s = ''.join(l)
        assert s == r'''
context         '@@ -51,8 +51,15 @@'
unmod    51  51 '<u>\t</u>begin();'
unmod    52  52 '<u>\t</u><i></i>'
add      53     '<u>\t</u>int foo;<u class="cr"></u>'
add      54     '<u>\t</u>int bar; <u class="cr"></u>'
add      55     '<u>\t</u>int baz;<u>\t</u><u class="cr"></u>'
add      56     '<u>\t</u>int space; <i></i>'
add      57     '<u>\t</u>int tab;<u>\t</u><i></i>'
add      58     '<u>\t</u><i></i>'
unmod    59  53 ' <i></i>'
del          54 '<u>\t</u>#define MAX_STEPS (48)'
add      60     '<u>\t</u><u class="cr"></u>'
add      61     '<u>\t</u>#define MAX_STEPS (64)<u class="cr"></u>'
unmod    62  55 ''
del          56 '<u>\t</u>#define MIN_STEPS (<del>48</del>)'
add      63     '<u>\t</u>#define MIN_STEPS (<ins>42</ins>)'
unmod    64  57 ''
del          58 '<u>\t</u>#define <del>MORE_STEPS</del><u>\t</u><del>+</del>(<del>48</del>)<del><u>\t</u></del><del><i></i></del>'
add      65     '<u>\t</u>#define <ins>LESS_STEPS</ins><u>\t</u>(<ins>42</ins>)<ins> <i></i></ins>'
'''
