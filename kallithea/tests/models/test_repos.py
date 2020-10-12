import pytest

from kallithea.lib.exceptions import AttachedForksError
from kallithea.model import db, meta
from kallithea.model.repo import RepoModel
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


class TestRepos(base.TestController):

    def teardown_method(self, method):
        meta.Session.remove()

    def test_remove_repo(self):
        repo = fixture.create_repo(name='test-repo-1')
        meta.Session().commit()

        RepoModel().delete(repo=repo)
        meta.Session().commit()

        assert db.Repository.get_by_repo_name(repo_name='test-repo-1') is None

    def test_remove_repo_repo_raises_exc_when_attached_forks(self):
        repo = fixture.create_repo(name='test-repo-1')
        meta.Session().commit()

        fixture.create_fork(repo.repo_name, 'test-repo-fork-1')
        meta.Session().commit()

        with pytest.raises(AttachedForksError):
            RepoModel().delete(repo=repo)
        # cleanup
        RepoModel().delete(repo='test-repo-fork-1')
        RepoModel().delete(repo='test-repo-1')
        meta.Session().commit()

    def test_remove_repo_delete_forks(self):
        repo = fixture.create_repo(name='test-repo-1')
        meta.Session().commit()

        fork = fixture.create_fork(repo.repo_name, 'test-repo-fork-1')
        meta.Session().commit()

        # fork of fork
        fixture.create_fork(fork.repo_name, 'test-repo-fork-fork-1')
        meta.Session().commit()

        RepoModel().delete(repo=repo, forks='delete')
        meta.Session().commit()

        assert db.Repository.get_by_repo_name(repo_name='test-repo-1') is None
        assert db.Repository.get_by_repo_name(repo_name='test-repo-fork-1') is None
        assert db.Repository.get_by_repo_name(repo_name='test-repo-fork-fork-1') is None

    def test_remove_repo_detach_forks(self):
        repo = fixture.create_repo(name='test-repo-1')
        meta.Session().commit()

        fork = fixture.create_fork(repo.repo_name, 'test-repo-fork-1')
        meta.Session().commit()

        # fork of fork
        fixture.create_fork(fork.repo_name, 'test-repo-fork-fork-1')
        meta.Session().commit()

        RepoModel().delete(repo=repo, forks='detach')
        meta.Session().commit()

        try:
            assert db.Repository.get_by_repo_name(repo_name='test-repo-1') is None
            assert db.Repository.get_by_repo_name(repo_name='test-repo-fork-1') is not None
            assert db.Repository.get_by_repo_name(repo_name='test-repo-fork-fork-1') is not None
        finally:
            RepoModel().delete(repo='test-repo-fork-fork-1')
            RepoModel().delete(repo='test-repo-fork-1')
            meta.Session().commit()
