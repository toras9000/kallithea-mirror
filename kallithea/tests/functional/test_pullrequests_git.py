import re

import pytest

from kallithea.controllers.pullrequests import PullrequestsController
from kallithea.model import meta
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


class TestPullrequestsController(base.TestController):

    def test_index(self):
        self.log_user()
        response = self.app.get(base.url(controller='pullrequests', action='index',
                                    repo_name=base.GIT_REPO))

    def test_create_trivial(self):
        self.log_user()
        response = self.app.post(base.url(controller='pullrequests', action='create',
                                     repo_name=base.GIT_REPO),
                                 {'org_repo': base.GIT_REPO,
                                  'org_ref': 'branch:master:5f2c6ee195929b0be80749243c18121c9864a3b3',
                                  'other_repo': base.GIT_REPO,
                                  'other_ref': 'tag:v0.2.2:137fea89f304a42321d40488091ee2ed419a3686',
                                  'pullrequest_title': 'title',
                                  'pullrequest_desc': 'description',
                                  '_session_csrf_secret_token': self.session_csrf_secret_token(),
                                 },
                                 status=302)
        # will redirect to URL like http://localhost/vcs_test_git/pull-request/1/_/master
        pull_request_id = int(response.location.split('/')[5])

        response = response.follow()
        assert response.status == '200 OK'
        response.mustcontain('Successfully opened new pull request')
        response.mustcontain('Git pull requests don&#39;t support iterating yet.')

        response = self.app.post(base.url('pullrequest_delete',
                                 repo_name=base.GIT_REPO, pull_request_id=pull_request_id),
                                 {
                                  '_session_csrf_secret_token': self.session_csrf_secret_token(),
                                 },
                                 status=302)
        response = response.follow()
        assert response.status == '200 OK'
        response.mustcontain('Successfully deleted pull request')


    def test_edit_with_invalid_reviewer(self):
        invalid_user_id = 99999
        self.log_user()
        # create a valid pull request
        response = self.app.post(base.url(controller='pullrequests', action='create',
                                     repo_name=base.GIT_REPO),
                                 {
                                  'org_repo': base.GIT_REPO,
                                  'org_ref': 'branch:master:5f2c6ee195929b0be80749243c18121c9864a3b3',
                                  'other_repo': base.GIT_REPO,
                                  'other_ref': 'tag:v0.2.2:137fea89f304a42321d40488091ee2ed419a3686',
                                  'pullrequest_title': 'title',
                                  'pullrequest_desc': 'description',
                                  '_session_csrf_secret_token': self.session_csrf_secret_token(),
                                 },
                                status=302)
        # location is of the form:
        # http://localhost/vcs_test_git/pull-request/54/_/title
        m = re.search(r'/pull-request/(\d+)/', response.location)
        assert m is not None
        pull_request_id = m.group(1)

        # edit it
        response = self.app.post(base.url(controller='pullrequests', action='post',
                                     repo_name=base.GIT_REPO, pull_request_id=pull_request_id),
                                 {
                                  'pullrequest_title': 'title',
                                  'pullrequest_desc': 'description',
                                  'owner': base.TEST_USER_ADMIN_LOGIN,
                                  '_session_csrf_secret_token': self.session_csrf_secret_token(),
                                  'review_members': [str(invalid_user_id)],
                                 },
                                 status=400)
        response.mustcontain('Invalid reviewer &quot;%s&quot; specified' % invalid_user_id)

@pytest.mark.usefixtures("test_context_fixture") # apply fixture for all test methods
class TestPullrequestsGetRepoRefs(base.TestController):

    def setup_method(self, method):
        self.repo_name = 'main'
        repo = fixture.create_repo(self.repo_name, repo_type='git')
        self.repo_scm_instance = repo.scm_instance
        meta.Session().commit()
        self.c = PullrequestsController()

    def teardown_method(self, method):
        fixture.destroy_repo('main')
        meta.Session().commit()
        meta.Session.remove()

    def test_repo_refs_empty_repo(self):
        # empty repo with no commits, no branches, no bookmarks, just one tag
        refs, default = self.c._get_repo_refs(self.repo_scm_instance)
        assert default == ''  # doesn't make sense, but better than nothing

    def test_repo_refs_one_commit_no_hints(self):
        cs0 = fixture.commit_change(self.repo_name, filename='file1',
                content='line1\n', message='commit1', vcs_type='git',
                parent=None, newfile=True)

        refs, default = self.c._get_repo_refs(self.repo_scm_instance)
        assert default == 'branch:master:%s' % cs0.raw_id
        assert ([('branch:master:%s' % cs0.raw_id, 'master')], 'Branches') in refs

    def test_repo_refs_one_commit_rev_hint(self):
        cs0 = fixture.commit_change(self.repo_name, filename='file1',
                content='line1\n', message='commit1', vcs_type='git',
                parent=None, newfile=True)

        refs, default = self.c._get_repo_refs(self.repo_scm_instance, rev=cs0.raw_id)
        expected = 'branch:master:%s' % cs0.raw_id
        assert default == expected
        assert ([(expected, 'master')], 'Branches') in refs

    def test_repo_refs_two_commits_no_hints(self):
        cs0 = fixture.commit_change(self.repo_name, filename='file1',
                content='line1\n', message='commit1', vcs_type='git',
                parent=None, newfile=True)
        cs1 = fixture.commit_change(self.repo_name, filename='file2',
                content='line2\n', message='commit2', vcs_type='git',
                parent=None, newfile=True)

        refs, default = self.c._get_repo_refs(self.repo_scm_instance)
        expected = 'branch:master:%s' % cs1.raw_id
        assert default == expected
        assert ([(expected, 'master')], 'Branches') in refs

    def test_repo_refs_two_commits_rev_hints(self):
        cs0 = fixture.commit_change(self.repo_name, filename='file1',
                content='line1\n', message='commit1', vcs_type='git',
                parent=None, newfile=True)
        cs1 = fixture.commit_change(self.repo_name, filename='file2',
                content='line2\n', message='commit2', vcs_type='git',
                parent=None, newfile=True)

        refs, default = self.c._get_repo_refs(self.repo_scm_instance, rev=cs0.raw_id)
        expected = 'rev:%s:%s' % (cs0.raw_id, cs0.raw_id)
        assert default == expected
        assert ([(expected, 'Changeset: %s' % cs0.raw_id[0:12])], 'Special') in refs
        assert ([('branch:master:%s' % cs1.raw_id, 'master')], 'Branches') in refs

        refs, default = self.c._get_repo_refs(self.repo_scm_instance, rev=cs1.raw_id)
        expected = 'branch:master:%s' % cs1.raw_id
        assert default == expected
        assert ([(expected, 'master')], 'Branches') in refs

    def test_repo_refs_two_commits_branch_hint(self):
        cs0 = fixture.commit_change(self.repo_name, filename='file1',
                content='line1\n', message='commit1', vcs_type='git',
                parent=None, newfile=True)
        cs1 = fixture.commit_change(self.repo_name, filename='file2',
                content='line2\n', message='commit2', vcs_type='git',
                parent=None, newfile=True)

        refs, default = self.c._get_repo_refs(self.repo_scm_instance, branch='master')
        expected = 'branch:master:%s' % cs1.raw_id
        assert default == expected
        assert ([(expected, 'master')], 'Branches') in refs

    def test_repo_refs_one_branch_no_hints(self):
        cs0 = fixture.commit_change(self.repo_name, filename='file1',
                content='line1\n', message='commit1', vcs_type='git',
                parent=None, newfile=True)
        # TODO
