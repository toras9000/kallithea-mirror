from kallithea.model import db, meta
from kallithea.model.repo_group import RepoGroupModel
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


class TestRepoGroupsController(base.TestController):

    def test_index(self):
        self.log_user()
        response = self.app.get(base.url('repos_groups'))
        response.mustcontain('"records": []')

    def test_new(self):
        self.log_user()
        response = self.app.get(base.url('new_repos_group'))

    def test_create(self):
        self.log_user()

        group_name = 'foo'

        # creation with form error
        response = self.app.post(base.url('repos_groups'),
                                         {'group_name': group_name,
                                          '_session_csrf_secret_token': self.session_csrf_secret_token()})
        response.mustcontain('name="group_name" type="text" value="%s"' % group_name)
        response.mustcontain('<!-- for: group_description -->')

        # creation
        response = self.app.post(base.url('repos_groups'),
                                         {'group_name': group_name,
                                         'group_description': 'lala',
                                         'parent_group_id': '-1',
                                         'group_copy_permissions': 'True',
                                          '_session_csrf_secret_token': self.session_csrf_secret_token()})
        self.checkSessionFlash(response, 'Created repository group %s' % group_name)

        # edit form
        response = self.app.get(base.url('edit_repo_group', group_name=group_name))
        response.mustcontain('>lala<')

        # edit with form error
        response = self.app.post(base.url('update_repos_group', group_name=group_name),
                                         {'group_name': group_name,
                                          '_session_csrf_secret_token': self.session_csrf_secret_token()})
        response.mustcontain('name="group_name" type="text" value="%s"' % group_name)
        response.mustcontain('<!-- for: group_description -->')

        # edit
        response = self.app.post(base.url('update_repos_group', group_name=group_name),
                                         {'group_name': group_name,
                                         'group_description': 'lolo',
                                          '_session_csrf_secret_token': self.session_csrf_secret_token()})
        self.checkSessionFlash(response, 'Updated repository group %s' % group_name)
        response = response.follow()
        response.mustcontain('name="group_name" type="text" value="%s"' % group_name)
        response.mustcontain(no='<!-- for: group_description -->')
        response.mustcontain('>lolo<')

        # listing
        response = self.app.get(base.url('repos_groups'))
        response.mustcontain('raw_name": "%s"' % group_name)

        # show
        response = self.app.get(base.url('repos_group', group_name=group_name))
        response.mustcontain('href="/_admin/repo_groups/%s/edit"' % group_name)

        # show ignores extra trailing slashes in the URL
        response = self.app.get(base.url('repos_group', group_name='%s//' % group_name))
        response.mustcontain('href="/_admin/repo_groups/%s/edit"' % group_name)

        # delete
        response = self.app.post(base.url('delete_repo_group', group_name=group_name),
                                 {'_session_csrf_secret_token': self.session_csrf_secret_token()})
        self.checkSessionFlash(response, 'Removed repository group %s' % group_name)

    def test_new_by_regular_user(self):
        self.log_user(base.TEST_USER_REGULAR_LOGIN, base.TEST_USER_REGULAR_PASS)
        response = self.app.get(base.url('new_repos_group'), status=403)

    def test_case_insensitivity(self):
        self.log_user()
        group_name = 'newgroup'
        response = self.app.post(base.url('repos_groups'),
                                 fixture._get_repo_group_create_params(group_name=group_name,
                                                                 _session_csrf_secret_token=self.session_csrf_secret_token()))
        # try to create repo group with swapped case
        swapped_group_name = group_name.swapcase()
        response = self.app.post(base.url('repos_groups'),
                                 fixture._get_repo_group_create_params(group_name=swapped_group_name,
                                                                 _session_csrf_secret_token=self.session_csrf_secret_token()))
        response.mustcontain('already exists')

        RepoGroupModel().delete(group_name)
        meta.Session().commit()

    def test_subgroup_deletion(self):
        self.log_user()
        parent = None
        parent_name = 'parent'
        sub = None
        sub_name = 'sub'
        sub_path = 'parent/sub'

        try:
            # create parent group
            assert db.RepoGroup.guess_instance(parent_name) is None
            response = self.app.post(
                base.url('repos_groups'),
                fixture._get_repo_group_create_params(
                    group_name=parent_name,
                    _session_csrf_secret_token=self.session_csrf_secret_token()
                )
            )
            parent = db.RepoGroup.guess_instance(parent_name)
            assert parent is not None

            # create sub group
            assert db.RepoGroup.guess_instance(sub_path) is None
            response = self.app.post(
                base.url('repos_groups'),
                fixture._get_repo_group_create_params(
                    group_name=sub_name,
                    parent_group_id=parent.group_id,
                    _session_csrf_secret_token=self.session_csrf_secret_token()
                )
            )
            sub = db.RepoGroup.guess_instance(sub_path)
            assert sub is not None

            # delete sub group
            response = self.app.post(
                base.url('delete_repo_group', group_name=sub_path),
                params={
                    '_session_csrf_secret_token': self.session_csrf_secret_token()
                },
            )
            sub = db.RepoGroup.guess_instance(sub_path)
            assert sub is None

        finally:
            if sub:
                RepoGroupModel().delete(sub)
            if parent:
                RepoGroupModel().delete(parent)
            meta.Session().commit()
