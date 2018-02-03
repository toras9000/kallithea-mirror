
import pytest

from kallithea.lib.vcs.nodes import FileNode
from kallithea.lib.vcs.exceptions import ChangesetDoesNotExistError

        assert self.repo.get_config_value('universal', 'foo', TEST_USER_CONFIG_FILE) == 'bar'
        assert self.repo.get_config_value('universal', 'nonexist', TEST_USER_CONFIG_FILE) == None
        assert self.repo.get_user_name(TEST_USER_CONFIG_FILE) == 'Foo Bar'
        assert self.repo.get_user_email(TEST_USER_CONFIG_FILE) == 'foo.bar@example.com'
        assert self.repo == self.repo
        assert self.repo != _repo
        assert self.repo != dummy()
        with pytest.raises(ChangesetDoesNotExistError):
class TestGitRepositoryGetDiff(RepositoryGetDiffTest):
        assert self.repo.get_diff(self.repo.EMPTY_CHANGESET, initial_rev) == '''diff --git a/foobar b/foobar