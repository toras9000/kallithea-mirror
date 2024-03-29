import re

from kallithea.model import db, meta
from kallithea.model.changeset_status import ChangesetStatusModel
from kallithea.tests import base


class TestChangeSetCommentsController(base.TestController):

    def setup_method(self, method):
        for x in db.ChangesetComment.query().all():
            meta.Session().delete(x)
        meta.Session().commit()

    def test_create(self):
        self.log_user()
        rev = '27cd5cce30c96924232dffcd24178a07ffeb5dfc'
        text = 'general comment on changeset'

        params = {'text': text, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='changeset', action='comment',
                                     repo_name=base.HG_REPO, revision=rev),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='changeset', action='index',
                                repo_name=base.HG_REPO, revision=rev))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 1 comment (0 inline, 1 general)'''
        )
        response.mustcontain(text)

        # test DB
        assert db.ChangesetComment.query().count() == 1

    def test_create_inline(self):
        self.log_user()
        rev = '27cd5cce30c96924232dffcd24178a07ffeb5dfc'
        text = 'inline comment on changeset'
        f_path = 'vcs/web/simplevcs/views/repository.py'
        line = 'n1'

        params = {'text': text, 'f_path': f_path, 'line': line, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='changeset', action='comment',
                                     repo_name=base.HG_REPO, revision=rev),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='changeset', action='index',
                                repo_name=base.HG_REPO, revision=rev))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 1 comment (1 inline, 0 general)'''
        )
        response.mustcontain(
            '''<div class="comments-list-chunk" '''
            '''data-f_path="vcs/web/simplevcs/views/repository.py" '''
            '''data-line_no="n1" data-target-id="vcswebsimplevcsviewsrepositorypy_n1">'''
        )
        response.mustcontain(text)

        # test DB
        assert db.ChangesetComment.query().count() == 1

    def test_create_with_mention(self):
        self.log_user()

        rev = '27cd5cce30c96924232dffcd24178a07ffeb5dfc'
        text = '@%s check CommentOnRevision' % base.TEST_USER_REGULAR_LOGIN

        params = {'text': text, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='changeset', action='comment',
                                     repo_name=base.HG_REPO, revision=rev),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='changeset', action='index',
                                repo_name=base.HG_REPO, revision=rev))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 1 comment (0 inline, 1 general)'''
        )
        response.mustcontain('<b>@%s</b> check CommentOnRevision' % base.TEST_USER_REGULAR_LOGIN)

        # test DB
        assert db.ChangesetComment.query().count() == 1

    def test_create_status_change(self):
        self.log_user()
        rev = '27cd5cce30c96924232dffcd24178a07ffeb5dfc'
        text = 'general comment on changeset'

        params = {'text': text, 'changeset_status': 'rejected',
                '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='changeset', action='comment',
                                     repo_name=base.HG_REPO, revision=rev),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='changeset', action='index',
                                repo_name=base.HG_REPO, revision=rev))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 1 comment (0 inline, 1 general)'''
        )
        response.mustcontain(text)

        # test DB
        assert db.ChangesetComment.query().count() == 1

        # check status
        status = ChangesetStatusModel().get_status(repo=base.HG_REPO, revision=rev)
        assert status == 'rejected'

    def test_delete(self):
        self.log_user()
        rev = '27cd5cce30c96924232dffcd24178a07ffeb5dfc'
        text = 'general comment on changeset to be deleted'

        params = {'text': text, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='changeset', action='comment',
                                     repo_name=base.HG_REPO, revision=rev),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})

        comments = db.ChangesetComment.query().all()
        assert len(comments) == 1
        comment_id = comments[0].comment_id

        self.app.post(base.url("changeset_comment_delete",
                                    repo_name=base.HG_REPO,
                                    comment_id=comment_id),
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})

        comments = db.ChangesetComment.query().all()
        assert len(comments) == 0

        response = self.app.get(base.url(controller='changeset', action='index',
                                repo_name=base.HG_REPO, revision=rev))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 0 comments (0 inline, 0 general)'''
        )
        response.mustcontain(no=text)


class TestPullrequestsCommentsController(base.TestController):

    def setup_method(self, method):
        for x in db.ChangesetComment.query().all():
            meta.Session().delete(x)
        meta.Session().commit()

    def _create_pr(self):
        response = self.app.post(base.url(controller='pullrequests', action='create',
                                     repo_name=base.HG_REPO),
                                 {'org_repo': base.HG_REPO,
                                  'org_ref': 'branch:stable:4f7e2131323e0749a740c0a56ab68ae9269c562a',
                                  'other_repo': base.HG_REPO,
                                  'other_ref': 'branch:default:96507bd11ecc815ebc6270fdf6db110928c09c1e',
                                  'pullrequest_title': 'title',
                                  'pullrequest_desc': 'description',
                                  '_session_csrf_secret_token': self.session_csrf_secret_token(),
                                 },
                                 status=302)
        pr_id = int(re.search(r'/pull-request/(\d+)/', response.location).group(1))
        return pr_id

    def test_create(self):
        self.log_user()
        pr_id = self._create_pr()

        text = 'general comment on pullrequest'
        params = {'text': text, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''))
        # PRs currently always have an initial 'Under Review' status change
        # that counts as a general comment, hence '2' in the test below. That
        # could be counted as a misfeature, to be reworked later.
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 2 comments (0 inline, 2 general)'''
        )
        response.mustcontain(text)

        # test DB
        assert db.ChangesetComment.query().count() == 2

    def test_create_inline(self):
        self.log_user()
        pr_id = self._create_pr()

        text = 'inline comment on changeset'
        f_path = 'vcs/web/simplevcs/views/repository.py'
        line = 'n1'
        params = {'text': text, 'f_path': f_path, 'line': line, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 2 comments (1 inline, 1 general)'''
        )
        response.mustcontain(
            '''<div class="comments-list-chunk" '''
            '''data-f_path="vcs/web/simplevcs/views/repository.py" '''
            '''data-line_no="n1" data-target-id="vcswebsimplevcsviewsrepositorypy_n1">'''
        )
        response.mustcontain(text)

        # test DB
        assert db.ChangesetComment.query().count() == 2

    def test_create_with_mention(self):
        self.log_user()
        pr_id = self._create_pr()

        text = '@%s check CommentOnRevision' % base.TEST_USER_REGULAR_LOGIN
        params = {'text': text, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 2 comments (0 inline, 2 general)'''
        )
        response.mustcontain('<b>@%s</b> check CommentOnRevision' % base.TEST_USER_REGULAR_LOGIN)

        # test DB
        assert db.ChangesetComment.query().count() == 2

    def test_create_status_change(self):
        self.log_user()
        pr_id = self._create_pr()

        text = 'general comment on pullrequest'
        params = {'text': text, 'changeset_status': 'rejected',
                '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''))
        # PRs currently always have an initial 'Under Review' status change
        # that counts as a general comment, hence '2' in the test below. That
        # could be counted as a misfeature, to be reworked later.
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 2 comments (0 inline, 2 general)'''
        )
        response.mustcontain(text)

        # test DB
        assert db.ChangesetComment.query().count() == 2

        # check status
        status = ChangesetStatusModel().get_status(repo=base.HG_REPO, pull_request=pr_id)
        assert status == 'rejected'

    def test_delete(self):
        self.log_user()
        pr_id = self._create_pr()

        text = 'general comment on changeset to be deleted'
        params = {'text': text, '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})

        comments = db.ChangesetComment.query().all()
        assert len(comments) == 2
        comment_id = comments[-1].comment_id

        self.app.post(base.url("pullrequest_comment_delete",
                                    repo_name=base.HG_REPO,
                                    comment_id=comment_id),
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})

        comments = db.ChangesetComment.query().all()
        assert len(comments) == 1

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''))
        response.mustcontain(
            '''<div class="comments-number">'''
            ''' 1 comment (0 inline, 1 general)'''
        )
        response.mustcontain(no=text)

    def test_close_pr(self):
        self.log_user()
        pr_id = self._create_pr()

        text = 'general comment on pullrequest'
        params = {'text': text, 'save_close': 'close',
                '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''))
        response.mustcontain(
            '''title (Closed)'''
        )
        response.mustcontain(text)

        # test DB
        assert db.PullRequest.get(pr_id).status == db.PullRequest.STATUS_CLOSED

    def test_delete_pr(self):
        self.log_user()
        pr_id = self._create_pr()

        text = 'general comment on pullrequest'
        params = {'text': text, 'save_delete': 'delete',
                '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        # Test response...
        assert response.status == '200 OK'

        response = self.app.get(base.url(controller='pullrequests', action='show',
                                repo_name=base.HG_REPO, pull_request_id=pr_id, extra=''), status=404)

        # test DB
        assert db.PullRequest.get(pr_id) is None

    def test_delete_closed_pr(self):
        self.log_user()
        pr_id = self._create_pr()

        # first close
        text = 'general comment on pullrequest'
        params = {'text': text, 'save_close': 'close',
                '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'})
        assert response.status == '200 OK'

        # attempt delete, should fail
        params = {'text': text, 'save_delete': 'delete',
                '_session_csrf_secret_token': self.session_csrf_secret_token()}
        response = self.app.post(base.url(controller='pullrequests', action='comment',
                                     repo_name=base.HG_REPO, pull_request_id=pr_id),
                                     params=params, extra_environ={'HTTP_X_PARTIAL_XHR': '1'}, status=403)

        # verify that PR still exists, in closed state
        assert db.PullRequest.get(pr_id).status == db.PullRequest.STATUS_CLOSED
