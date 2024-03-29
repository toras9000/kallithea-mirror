# -*- coding: utf-8 -*-
import formencode
import pytest

from kallithea.model import meta
from kallithea.model import validators as v
from kallithea.model.repo_group import RepoGroupModel
from kallithea.model.user_group import UserGroupModel
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


@pytest.mark.usefixtures("test_context_fixture") # apply fixture for all test methods
class TestRepoGroups(base.TestController):

    def teardown_method(self, method):
        meta.Session.remove()

    def test_Message_extractor(self):
        validator = v.ValidUsername()
        with pytest.raises(formencode.Invalid):
            validator.to_python('default')

        class StateObj(object):
            pass

        with pytest.raises(formencode.Invalid):
            validator.to_python('default', StateObj)

    def test_ValidUsername(self):
        validator = v.ValidUsername()

        with pytest.raises(formencode.Invalid):
            validator.to_python('default')
        with pytest.raises(formencode.Invalid):
            validator.to_python('new_user')
        with pytest.raises(formencode.Invalid):
            validator.to_python('.,')
        with pytest.raises(formencode.Invalid):
            validator.to_python(base.TEST_USER_ADMIN_LOGIN)
        assert 'test' == validator.to_python('test')

        validator = v.ValidUsername(edit=True, old_data={'user_id': 1})

    def test_ValidRepoUser(self):
        validator = v.ValidRepoUser()
        with pytest.raises(formencode.Invalid):
            validator.to_python('nouser')
        assert base.TEST_USER_ADMIN_LOGIN == validator.to_python(base.TEST_USER_ADMIN_LOGIN)

    def test_ValidUserGroup(self):
        validator = v.ValidUserGroup()
        with pytest.raises(formencode.Invalid):
            validator.to_python('default')
        with pytest.raises(formencode.Invalid):
            validator.to_python('.,')

        gr = fixture.create_user_group('test')
        gr2 = fixture.create_user_group('tes2')
        meta.Session().commit()
        with pytest.raises(formencode.Invalid):
            validator.to_python('test')
        assert gr.users_group_id is not None
        validator = v.ValidUserGroup(edit=True,
                                    old_data={'users_group_id':
                                              gr2.users_group_id})

        with pytest.raises(formencode.Invalid):
            validator.to_python('test')
        with pytest.raises(formencode.Invalid):
            validator.to_python('TesT')
        with pytest.raises(formencode.Invalid):
            validator.to_python('TEST')
        UserGroupModel().delete(gr)
        UserGroupModel().delete(gr2)
        meta.Session().commit()

    def test_ValidRepoGroup(self):
        validator = v.ValidRepoGroup()
        model = RepoGroupModel()
        with pytest.raises(formencode.Invalid):
            validator.to_python({'group_name': base.HG_REPO, })
        gr = model.create(group_name='test_gr', group_description='desc',
                          parent=None,
                          just_db=True,
                          owner=base.TEST_USER_ADMIN_LOGIN)
        with pytest.raises(formencode.Invalid):
            validator.to_python({'group_name': gr.group_name, })

        validator = v.ValidRepoGroup(edit=True,
                                      old_data={'group_id':  gr.group_id})
        with pytest.raises(formencode.Invalid):
            validator.to_python({
                                        'group_name': gr.group_name + 'n',
                                        'parent_group_id': gr.group_id
                                        })
        model.delete(gr)

    def test_ValidPassword(self):
        validator = v.ValidPassword()
        assert 'lol' == validator.to_python('lol')
        assert validator.to_python(None) is None
        with pytest.raises(formencode.Invalid):
            validator.to_python('ąćżź')

    def test_ValidPasswordsMatch(self):
        validator = v.ValidPasswordsMatch('new_password', 'password_confirmation')
        with pytest.raises(formencode.Invalid):
            validator.to_python({'new_password': 'pass',
                                          'password_confirmation': 'pass2'})

        with pytest.raises(formencode.Invalid):
            validator.to_python({'new_password': 'pass',
                                          'password_confirmation': 'pass2'})

        assert {'new_password': 'pass',
                          'password_confirmation': 'pass'} == validator.to_python({'new_password': 'pass',
                                         'password_confirmation': 'pass'})

        assert {'new_password': 'pass',
                          'password_confirmation': 'pass'} == validator.to_python({'new_password': 'pass',
                                         'password_confirmation': 'pass'})

    def test_ValidAuth(self):
        validator = v.ValidAuth()
        valid_creds = {
            'username': base.TEST_USER_REGULAR2_LOGIN,
            'password': base.TEST_USER_REGULAR2_PASS,
        }
        invalid_creds = {
            'username': 'err',
            'password': 'err',
        }
        assert valid_creds == validator.to_python(valid_creds)
        with pytest.raises(formencode.Invalid):
            validator.to_python(invalid_creds)

    def test_ValidRepoName(self):
        validator = v.ValidRepoName()

        with pytest.raises(formencode.Invalid):
            validator.to_python({'repo_name': ''})

        with pytest.raises(formencode.Invalid):
            validator.to_python({'repo_name': base.HG_REPO})

        gr = RepoGroupModel().create(group_name='group_test',
                                      group_description='desc',
                                      parent=None,
                                      owner=base.TEST_USER_ADMIN_LOGIN)
        with pytest.raises(formencode.Invalid):
            validator.to_python({'repo_name': gr.group_name})

        # TODO: write an error case for that ie. create a repo withinh a group
#        self.assertRaises(formencode.Invalid,
#                          validator.to_python, {'repo_name': 'some',
#                                                'repo_group': gr.group_id})

    def test_ValidForkName(self):
        # this uses ValidRepoName validator
        assert True

    @base.parametrize('name,expected', [
        ('test', 'test'), ('lolz!', 'lolz'), ('  aavv', 'aavv'),
        ('ala ma kota', 'ala-ma-kota'), ('@nooo', 'nooo'),
        ('$!haha lolz !', 'haha-lolz'), ('$$$$$', ''), ('{}OK!', 'OK'),
        ('/]re po', 're-po')])
    def test_SlugifyName(self, name, expected):
        validator = v.SlugifyName()
        assert expected == validator.to_python(name)

    def test_ValidCloneUri(self):
            # TODO: write this one
            pass

    def test_ValidForkType(self):
            validator = v.ValidForkType(old_data={'repo_type': 'hg'})
            assert 'hg' == validator.to_python('hg')
            with pytest.raises(formencode.Invalid):
                validator.to_python('git')

    def test_ValidPerms(self):
            # TODO: write this one
            pass

    def test_ValidSettings(self):
        validator = v.ValidSettings()
        assert {'pass': 'pass'} == validator.to_python(value={'user': 'test',
                                                    'pass': 'pass'})

        assert {'user2': 'test', 'pass': 'pass'} == validator.to_python(value={'user2': 'test',
                                                    'pass': 'pass'})

    def test_ValidPath(self):
            validator = v.ValidPath()
            assert base.TESTS_TMP_PATH == validator.to_python(base.TESTS_TMP_PATH)
            with pytest.raises(formencode.Invalid):
                validator.to_python('/no_such_dir')

    def test_UniqSystemEmail(self):
        validator = v.UniqSystemEmail(old_data={})

        assert 'mail@python.org' == validator.to_python('MaiL@Python.org')

        email = base.TEST_USER_REGULAR2_EMAIL
        with pytest.raises(formencode.Invalid):
            validator.to_python(email)

    def test_ValidSystemEmail(self):
        validator = v.ValidSystemEmail()
        email = base.TEST_USER_REGULAR2_EMAIL

        assert email == validator.to_python(email)
        with pytest.raises(formencode.Invalid):
            validator.to_python('err')

    def test_LdapLibValidator(self):
        if base.ldap_lib_installed:
            validator = v.LdapLibValidator()
            assert "DN" == validator.to_python('DN')
        else:
            validator = v.LdapLibValidator()
            with pytest.raises(v.LdapImportError):
                validator.to_python('err')

    def test_AttrLoginValidator(self):
        validator = v.AttrLoginValidator()
        assert 'DN_attr' == validator.to_python('DN_attr')
