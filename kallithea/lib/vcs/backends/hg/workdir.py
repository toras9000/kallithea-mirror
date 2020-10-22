import mercurial.merge

from kallithea.lib.vcs.backends.base import BaseWorkdir
from kallithea.lib.vcs.exceptions import BranchDoesNotExistError
from kallithea.lib.vcs.utils import ascii_bytes, ascii_str, safe_str


class MercurialWorkdir(BaseWorkdir):

    def get_branch(self):
        return safe_str(self.repository._repo.dirstate.branch())

    def get_changeset(self):
        wk_dir_id = ascii_str(self.repository._repo[None].parents()[0].hex())
        return self.repository.get_changeset(wk_dir_id)

    def checkout_branch(self, branch=None):
        if branch is None:
            branch = self.repository.DEFAULT_BRANCH_NAME
        if branch not in self.repository.branches:
            raise BranchDoesNotExistError

        raw_id = self.repository.branches[branch]
        try:
            mercurial.merge.update(self.repository._repo[ascii_bytes(raw_id)])
        except TypeError:  # mergeupdate() missing 3 required positional arguments: 'node', 'branchmerge', and 'force'
            # update-update was introduced with Mercurial 5.6 (2c86b9587740/c1b603cdc95a)
            mercurial.merge.update(self.repository._repo, ascii_bytes(raw_id), False, False, None)
