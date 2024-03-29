# -*- coding: utf-8 -*-

import os
import urllib.parse

import mock
import pytest

import kallithea
from kallithea.lib import vcs
from kallithea.model import db, meta
from kallithea.model.repo import RepoModel
from kallithea.model.repo_group import RepoGroupModel
from kallithea.model.user import UserModel
from kallithea.tests import base
from kallithea.tests.fixture import Fixture, raise_exception


fixture = Fixture()


def _get_permission_for_user(user, repo):
    perm = db.UserRepoToPerm.query() \
                .filter(db.UserRepoToPerm.repository ==
                        db.Repository.get_by_repo_name(repo)) \
                .filter(db.UserRepoToPerm.user == db.User.get_by_username(user)) \
                .all()
    return perm


class _BaseTestCase(base.TestController):
    """
    Write all tests here
    """
    REPO = None
    REPO_TYPE = None
    NEW_REPO = None
    OTHER_TYPE_REPO = None
    OTHER_TYPE = None

    def test_index(self):
        self.log_user()
        response = self.app.get(base.url('repos'))

    def test_create(self):
        self.log_user()
        repo_name = self.NEW_REPO
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        ## run the check page that triggers the flash message
        response = self.app.get(base.url('repo_check_home', repo_name=repo_name))
        assert response.json == {'result': True}
        self.checkSessionFlash(response,
                               'Created repository <a href="/%s">%s</a>'
                               % (repo_name, repo_name))

        # test if the repo was created in the database
        new_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name).one()

        assert new_repo.repo_name == repo_name
        assert new_repo.description == description

        # test if the repository is visible in the list ?
        response = self.app.get(base.url('summary_home', repo_name=repo_name))
        response.mustcontain(repo_name)
        response.mustcontain(self.REPO_TYPE)

        # test if the repository was created on filesystem
        try:
            vcs.get_repo(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name))
        except vcs.exceptions.VCSError:
            pytest.fail('no repo %s in filesystem' % repo_name)

        RepoModel().delete(repo_name)
        meta.Session().commit()

    def test_case_insensitivity(self):
        self.log_user()
        repo_name = self.NEW_REPO
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                                 fixture._get_repo_create_params(repo_private=False,
                                                                 repo_name=repo_name,
                                                                 repo_type=self.REPO_TYPE,
                                                                 repo_description=description,
                                                                 _session_csrf_secret_token=self.session_csrf_secret_token()))
        # try to create repo with swapped case
        swapped_repo_name = repo_name.swapcase()
        response = self.app.post(base.url('repos'),
                                 fixture._get_repo_create_params(repo_private=False,
                                                                 repo_name=swapped_repo_name,
                                                                 repo_type=self.REPO_TYPE,
                                                                 repo_description=description,
                                                                 _session_csrf_secret_token=self.session_csrf_secret_token()))
        response.mustcontain('already exists')

        RepoModel().delete(repo_name)
        meta.Session().commit()

    def test_create_in_group(self):
        self.log_user()

        ## create GROUP
        group_name = 'sometest_%s' % self.REPO_TYPE
        gr = RepoGroupModel().create(group_name=group_name,
                                     group_description='test',
                                     owner=base.TEST_USER_ADMIN_LOGIN)
        meta.Session().commit()

        repo_name = 'ingroup'
        repo_name_full = kallithea.URL_SEP.join([group_name, repo_name])
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                repo_group=gr.group_id,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        ## run the check page that triggers the flash message
        response = self.app.get(base.url('repo_check_home', repo_name=repo_name_full))
        assert response.json == {'result': True}
        self.checkSessionFlash(response,
                               'Created repository <a href="/%s">%s</a>'
                               % (repo_name_full, repo_name_full))
        # test if the repo was created in the database
        new_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name_full).one()
        new_repo_id = new_repo.repo_id

        assert new_repo.repo_name == repo_name_full
        assert new_repo.description == description

        # test if the repository is visible in the list ?
        response = self.app.get(base.url('summary_home', repo_name=repo_name_full))
        response.mustcontain(repo_name_full)
        response.mustcontain(self.REPO_TYPE)

        inherited_perms = db.UserRepoToPerm.query() \
            .filter(db.UserRepoToPerm.repository_id == new_repo_id).all()
        assert len(inherited_perms) == 1

        # test if the repository was created on filesystem
        try:
            vcs.get_repo(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name_full))
        except vcs.exceptions.VCSError:
            RepoGroupModel().delete(group_name)
            meta.Session().commit()
            pytest.fail('no repo %s in filesystem' % repo_name)

        RepoModel().delete(repo_name_full)
        RepoGroupModel().delete(group_name)
        meta.Session().commit()

    def test_create_in_group_without_needed_permissions(self):
        usr = self.log_user(base.TEST_USER_REGULAR_LOGIN, base.TEST_USER_REGULAR_PASS)
        # avoid spurious RepoGroup DetachedInstanceError ...
        session_csrf_secret_token = self.session_csrf_secret_token()
        # revoke
        user_model = UserModel()
        # disable fork and create on default user
        user_model.revoke_perm(db.User.DEFAULT_USER_NAME, 'hg.create.repository')
        user_model.grant_perm(db.User.DEFAULT_USER_NAME, 'hg.create.none')
        user_model.revoke_perm(db.User.DEFAULT_USER_NAME, 'hg.fork.repository')
        user_model.grant_perm(db.User.DEFAULT_USER_NAME, 'hg.fork.none')

        # disable on regular user
        user_model.revoke_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.create.repository')
        user_model.grant_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.create.none')
        user_model.revoke_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.fork.repository')
        user_model.grant_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.fork.none')
        meta.Session().commit()

        ## create GROUP
        group_name = 'reg_sometest_%s' % self.REPO_TYPE
        gr = RepoGroupModel().create(group_name=group_name,
                                     group_description='test',
                                     owner=base.TEST_USER_ADMIN_LOGIN)
        meta.Session().commit()

        group_name_allowed = 'reg_sometest_allowed_%s' % self.REPO_TYPE
        gr_allowed = RepoGroupModel().create(group_name=group_name_allowed,
                                     group_description='test',
                                     owner=base.TEST_USER_REGULAR_LOGIN)
        meta.Session().commit()

        repo_name = 'ingroup'
        repo_name_full = kallithea.URL_SEP.join([group_name, repo_name])
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                repo_group=gr.group_id,
                                                _session_csrf_secret_token=session_csrf_secret_token))

        response.mustcontain('Invalid value')

        # user is allowed to create in this group
        repo_name = 'ingroup'
        repo_name_full = kallithea.URL_SEP.join([group_name_allowed, repo_name])
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                repo_group=gr_allowed.group_id,
                                                _session_csrf_secret_token=session_csrf_secret_token))

        ## run the check page that triggers the flash message
        response = self.app.get(base.url('repo_check_home', repo_name=repo_name_full))
        assert response.json == {'result': True}
        self.checkSessionFlash(response,
                               'Created repository <a href="/%s">%s</a>'
                               % (repo_name_full, repo_name_full))
        # test if the repo was created in the database
        new_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name_full).one()
        new_repo_id = new_repo.repo_id

        assert new_repo.repo_name == repo_name_full
        assert new_repo.description == description

        # test if the repository is visible in the list ?
        response = self.app.get(base.url('summary_home', repo_name=repo_name_full))
        response.mustcontain(repo_name_full)
        response.mustcontain(self.REPO_TYPE)

        inherited_perms = db.UserRepoToPerm.query() \
            .filter(db.UserRepoToPerm.repository_id == new_repo_id).all()
        assert len(inherited_perms) == 1

        # test if the repository was created on filesystem
        try:
            vcs.get_repo(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name_full))
        except vcs.exceptions.VCSError:
            RepoGroupModel().delete(group_name)
            meta.Session().commit()
            pytest.fail('no repo %s in filesystem' % repo_name)

        RepoModel().delete(repo_name_full)
        RepoGroupModel().delete(group_name)
        RepoGroupModel().delete(group_name_allowed)
        meta.Session().commit()

    def test_create_in_group_inherit_permissions(self):
        self.log_user()

        ## create GROUP
        group_name = 'sometest_%s' % self.REPO_TYPE
        gr = RepoGroupModel().create(group_name=group_name,
                                     group_description='test',
                                     owner=base.TEST_USER_ADMIN_LOGIN)
        perm = db.Permission.get_by_key('repository.write')
        RepoGroupModel().grant_user_permission(gr, base.TEST_USER_REGULAR_LOGIN, perm)

        ## add repo permissions
        meta.Session().commit()

        repo_name = 'ingroup_inherited_%s' % self.REPO_TYPE
        repo_name_full = kallithea.URL_SEP.join([group_name, repo_name])
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                repo_group=gr.group_id,
                                                repo_copy_permissions=True,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))

        ## run the check page that triggers the flash message
        response = self.app.get(base.url('repo_check_home', repo_name=repo_name_full))
        self.checkSessionFlash(response,
                               'Created repository <a href="/%s">%s</a>'
                               % (repo_name_full, repo_name_full))
        # test if the repo was created in the database
        new_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name_full).one()
        new_repo_id = new_repo.repo_id

        assert new_repo.repo_name == repo_name_full
        assert new_repo.description == description

        # test if the repository is visible in the list ?
        response = self.app.get(base.url('summary_home', repo_name=repo_name_full))
        response.mustcontain(repo_name_full)
        response.mustcontain(self.REPO_TYPE)

        # test if the repository was created on filesystem
        try:
            vcs.get_repo(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name_full))
        except vcs.exceptions.VCSError:
            RepoGroupModel().delete(group_name)
            meta.Session().commit()
            pytest.fail('no repo %s in filesystem' % repo_name)

        # check if inherited permissiona are applied
        inherited_perms = db.UserRepoToPerm.query() \
            .filter(db.UserRepoToPerm.repository_id == new_repo_id).all()
        assert len(inherited_perms) == 2

        assert base.TEST_USER_REGULAR_LOGIN in [x.user.username
                                                    for x in inherited_perms]
        assert 'repository.write' in [x.permission.permission_name
                                               for x in inherited_perms]

        RepoModel().delete(repo_name_full)
        RepoGroupModel().delete(group_name)
        meta.Session().commit()

    def test_create_remote_repo_wrong_clone_uri(self):
        self.log_user()
        repo_name = self.NEW_REPO
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                clone_uri='http://127.0.0.1/repo',
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        response.mustcontain('Invalid repository URL')

    def test_create_remote_repo_wrong_clone_uri_hg_svn(self):
        self.log_user()
        repo_name = self.NEW_REPO
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                clone_uri='svn+http://127.0.0.1/repo',
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        response.mustcontain('Invalid repository URL')

    def test_create_remote_repo_wrong_clone_uri_http_auth(self):
        self.log_user()
        repo_name = self.NEW_REPO
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                clone_uri='http://user:pass@127.0.0.1/repo',
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        response.mustcontain('Invalid repository URL')

    def test_delete(self):
        self.log_user()
        repo_name = 'vcs_test_new_to_delete_%s' % self.REPO_TYPE
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_type=self.REPO_TYPE,
                                                repo_name=repo_name,
                                                repo_description=description,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        ## run the check page that triggers the flash message
        response = self.app.get(base.url('repo_check_home', repo_name=repo_name))
        self.checkSessionFlash(response,
                               'Created repository <a href="/%s">%s</a>'
                               % (repo_name, repo_name))
        # test if the repo was created in the database
        new_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name).one()

        assert new_repo.repo_name == repo_name
        assert new_repo.description == description

        # test if the repository is visible in the list ?
        response = self.app.get(base.url('summary_home', repo_name=repo_name))
        response.mustcontain(repo_name)
        response.mustcontain(self.REPO_TYPE)

        # test if the repository was created on filesystem
        try:
            vcs.get_repo(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name))
        except vcs.exceptions.VCSError:
            pytest.fail('no repo %s in filesystem' % repo_name)

        response = self.app.post(base.url('delete_repo', repo_name=repo_name),
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})

        self.checkSessionFlash(response, 'Deleted repository %s' % (repo_name))

        response.follow()

        # check if repo was deleted from db
        deleted_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name).scalar()

        assert deleted_repo is None

        assert os.path.isdir(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name)) == False

    def test_delete_non_ascii(self):
        self.log_user()
        non_ascii = "ąęł"
        repo_name = "%s%s" % (self.NEW_REPO, non_ascii)
        description = 'description for newly created repo' + non_ascii
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        ## run the check page that triggers the flash message
        response = self.app.get(base.url('repo_check_home', repo_name=repo_name))
        assert response.json == {'result': True}
        self.checkSessionFlash(response,
                               'Created repository <a href="/%s">%s</a>'
                               % (urllib.parse.quote(repo_name), repo_name))
        # test if the repo was created in the database
        new_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name).one()

        assert new_repo.repo_name == repo_name
        assert new_repo.description == description

        # test if the repository is visible in the list ?
        response = self.app.get(base.url('summary_home', repo_name=repo_name))
        response.mustcontain(repo_name)
        response.mustcontain(self.REPO_TYPE)

        # test if the repository was created on filesystem
        try:
            vcs.get_repo(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name))
        except vcs.exceptions.VCSError:
            pytest.fail('no repo %s in filesystem' % repo_name)

        response = self.app.post(base.url('delete_repo', repo_name=repo_name),
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})
        self.checkSessionFlash(response, 'Deleted repository %s' % (repo_name))
        response.follow()

        # check if repo was deleted from db
        deleted_repo = meta.Session().query(db.Repository) \
            .filter(db.Repository.repo_name == repo_name).scalar()

        assert deleted_repo is None

        assert os.path.isdir(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name)) == False

    def test_delete_repo_with_group(self):
        # TODO:
        pass

    def test_delete_browser_fakeout(self):
        response = self.app.post(base.url('delete_repo', repo_name=self.REPO),
                                 params=dict(_session_csrf_secret_token=self.session_csrf_secret_token()))

    def test_show(self):
        self.log_user()
        response = self.app.get(base.url('summary_home', repo_name=self.REPO))

    def test_edit(self):
        response = self.app.get(base.url('edit_repo', repo_name=self.REPO))

    def test_set_private_flag_sets_default_to_none(self):
        self.log_user()
        # initially repository perm should be read
        perm = _get_permission_for_user(user='default', repo=self.REPO)
        assert len(perm), 1
        assert perm[0].permission.permission_name == 'repository.read'
        assert db.Repository.get_by_repo_name(self.REPO).private == False

        response = self.app.post(base.url('update_repo', repo_name=self.REPO),
                        fixture._get_repo_create_params(repo_private=1,
                                                repo_name=self.REPO,
                                                repo_type=self.REPO_TYPE,
                                                owner=base.TEST_USER_ADMIN_LOGIN,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        self.checkSessionFlash(response,
                               msg='Repository %s updated successfully' % (self.REPO))
        assert db.Repository.get_by_repo_name(self.REPO).private == True

        # now the repo default permission should be None
        perm = _get_permission_for_user(user='default', repo=self.REPO)
        assert len(perm), 1
        assert perm[0].permission.permission_name == 'repository.none'

        response = self.app.post(base.url('update_repo', repo_name=self.REPO),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=self.REPO,
                                                repo_type=self.REPO_TYPE,
                                                owner=base.TEST_USER_ADMIN_LOGIN,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))
        self.checkSessionFlash(response,
                               msg='Repository %s updated successfully' % (self.REPO))
        assert db.Repository.get_by_repo_name(self.REPO).private == False

        # we turn off private now the repo default permission should stay None
        perm = _get_permission_for_user(user='default', repo=self.REPO)
        assert len(perm), 1
        assert perm[0].permission.permission_name == 'repository.none'

        # update this permission back
        perm[0].permission = db.Permission.get_by_key('repository.read')
        meta.Session().commit()

    def test_set_repo_fork_has_no_self_id(self):
        self.log_user()
        repo = db.Repository.get_by_repo_name(self.REPO)
        response = self.app.get(base.url('edit_repo_advanced', repo_name=self.REPO))
        opt = """<option value="%s">%s</option>""" % (repo.repo_id, self.REPO)
        response.mustcontain(no=[opt])

    def test_set_fork_of_other_repo(self):
        self.log_user()
        other_repo = 'other_%s' % self.REPO_TYPE
        fixture.create_repo(other_repo, repo_type=self.REPO_TYPE)
        repo = db.Repository.get_by_repo_name(self.REPO)
        repo2 = db.Repository.get_by_repo_name(other_repo)
        response = self.app.post(base.url('edit_repo_advanced_fork', repo_name=self.REPO),
                                params=dict(id_fork_of=repo2.repo_id, _session_csrf_secret_token=self.session_csrf_secret_token()))
        repo = db.Repository.get_by_repo_name(self.REPO)
        repo2 = db.Repository.get_by_repo_name(other_repo)
        self.checkSessionFlash(response,
            'Marked repository %s as fork of %s' % (repo.repo_name, repo2.repo_name))

        assert repo.fork == repo2
        response = response.follow()
        # check if given repo is selected

        opt = """<option value="%s" selected="selected">%s</option>""" % (
                    repo2.repo_id, repo2.repo_name)
        response.mustcontain(opt)

        fixture.destroy_repo(other_repo, forks='detach')

    def test_set_fork_of_other_type_repo(self):
        self.log_user()
        repo = db.Repository.get_by_repo_name(self.REPO)
        repo2 = db.Repository.get_by_repo_name(self.OTHER_TYPE_REPO)
        response = self.app.post(base.url('edit_repo_advanced_fork', repo_name=self.REPO),
                                params=dict(id_fork_of=repo2.repo_id, _session_csrf_secret_token=self.session_csrf_secret_token()))
        repo = db.Repository.get_by_repo_name(self.REPO)
        repo2 = db.Repository.get_by_repo_name(self.OTHER_TYPE_REPO)
        self.checkSessionFlash(response,
            'Cannot set repository as fork of repository with other type')

    def test_set_fork_of_none(self):
        self.log_user()
        ## mark it as None
        response = self.app.post(base.url('edit_repo_advanced_fork', repo_name=self.REPO),
                                params=dict(id_fork_of=None, _session_csrf_secret_token=self.session_csrf_secret_token()))
        repo = db.Repository.get_by_repo_name(self.REPO)
        repo2 = db.Repository.get_by_repo_name(self.OTHER_TYPE_REPO)
        self.checkSessionFlash(response,
                               'Marked repository %s as fork of %s'
                               % (repo.repo_name, "Nothing"))
        assert repo.fork is None

    def test_set_fork_of_same_repo(self):
        self.log_user()
        repo = db.Repository.get_by_repo_name(self.REPO)
        response = self.app.post(base.url('edit_repo_advanced_fork', repo_name=self.REPO),
                                params=dict(id_fork_of=repo.repo_id, _session_csrf_secret_token=self.session_csrf_secret_token()))
        self.checkSessionFlash(response,
                               'An error occurred during this operation')

    def test_create_on_top_level_without_permissions(self):
        usr = self.log_user(base.TEST_USER_REGULAR_LOGIN, base.TEST_USER_REGULAR_PASS)
        # revoke
        user_model = UserModel()
        # disable fork and create on default user
        user_model.revoke_perm(db.User.DEFAULT_USER_NAME, 'hg.create.repository')
        user_model.grant_perm(db.User.DEFAULT_USER_NAME, 'hg.create.none')
        user_model.revoke_perm(db.User.DEFAULT_USER_NAME, 'hg.fork.repository')
        user_model.grant_perm(db.User.DEFAULT_USER_NAME, 'hg.fork.none')

        # disable on regular user
        user_model.revoke_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.create.repository')
        user_model.grant_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.create.none')
        user_model.revoke_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.fork.repository')
        user_model.grant_perm(base.TEST_USER_REGULAR_LOGIN, 'hg.fork.none')
        meta.Session().commit()


        user = db.User.get(usr['user_id'])

        repo_name = self.NEW_REPO + 'no_perms'
        description = 'description for newly created repo'
        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))

        response.mustcontain('<span class="error-message">Invalid value</span>')

        RepoModel().delete(repo_name)
        meta.Session().commit()

    @mock.patch.object(RepoModel, '_create_filesystem_repo', raise_exception)
    def test_create_repo_when_filesystem_op_fails(self):
        self.log_user()
        repo_name = self.NEW_REPO
        description = 'description for newly created repo'

        response = self.app.post(base.url('repos'),
                        fixture._get_repo_create_params(repo_private=False,
                                                repo_name=repo_name,
                                                repo_type=self.REPO_TYPE,
                                                repo_description=description,
                                                _session_csrf_secret_token=self.session_csrf_secret_token()))

        self.checkSessionFlash(response,
                               'Error creating repository %s' % repo_name)
        # repo must not be in db
        repo = db.Repository.get_by_repo_name(repo_name)
        assert repo is None

        # repo must not be in filesystem !
        assert not os.path.isdir(os.path.join(db.Ui.get_by_key('paths', '/').ui_value, repo_name))


class TestAdminReposControllerGIT(_BaseTestCase):
    REPO = base.GIT_REPO
    REPO_TYPE = 'git'
    NEW_REPO = base.NEW_GIT_REPO
    OTHER_TYPE_REPO = base.HG_REPO
    OTHER_TYPE = 'hg'


class TestAdminReposControllerHG(_BaseTestCase):
    REPO = base.HG_REPO
    REPO_TYPE = 'hg'
    NEW_REPO = base.NEW_HG_REPO
    OTHER_TYPE_REPO = base.GIT_REPO
    OTHER_TYPE = 'git'

    def test_permanent_url_protocol_access(self):
        repo = db.Repository.get_by_repo_name(self.REPO)
        permanent_name = '_%d' % repo.repo_id

        # 400 Bad Request - Unable to detect pull/push action
        self.app.get(base.url('summary_home', repo_name=permanent_name),
            extra_environ={'HTTP_ACCEPT': 'application/mercurial'},
            status=400,
        )
