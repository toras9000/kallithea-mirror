import pytest

from kallithea.model import db, meta
from kallithea.model.user import UserModel
from kallithea.model.user_group import UserGroupModel
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


class TestUser(base.TestController):

    @classmethod
    def setup_class(cls):
        meta.Session.remove()

    def teardown_method(self, method):
        meta.Session.remove()

    def test_create_and_remove(self):
        usr = UserModel().create_or_update(username='test_user',
                                           password='qweqwe',
                                           email='u232@example.com',
                                           firstname='u1', lastname='u1')
        meta.Session().commit()
        assert db.User.get_by_username('test_user') == usr
        assert db.User.get_by_username('test_USER', case_insensitive=True) == usr
        # User.get_by_username without explicit request for case insensitivty
        # will use database case sensitivity. The following will thus return
        # None on for example PostgreSQL but find test_user on MySQL - we are
        # fine with leaving that as undefined as long as it doesn't crash.
        db.User.get_by_username('test_USER', case_insensitive=False)

        # make user group
        user_group = fixture.create_user_group('some_example_group')
        meta.Session().commit()

        UserGroupModel().add_user_to_group(user_group, usr)
        meta.Session().commit()

        assert db.UserGroup.get(user_group.users_group_id) == user_group
        assert db.UserGroupMember.query().count() == 1
        UserModel().delete(usr.user_id)
        meta.Session().commit()

        assert db.UserGroupMember.query().all() == []

    def test_additional_email_as_main(self):
        usr = UserModel().create_or_update(username='test_user',
                                           password='qweqwe',
                                     email='main_email@example.com',
                                     firstname='u1', lastname='u1')
        meta.Session().commit()

        with pytest.raises(AttributeError):
            m = db.UserEmailMap()
            m.email = 'main_email@example.com'
            m.user = usr
            meta.Session().add(m)
            meta.Session().commit()

        UserModel().delete(usr.user_id)
        meta.Session().commit()

    def test_extra_email_map(self):
        usr = UserModel().create_or_update(username='test_user',
                                           password='qweqwe',
                                     email='main_email@example.com',
                                     firstname='u1', lastname='u1')
        meta.Session().commit()

        m = db.UserEmailMap()
        m.email = 'main_email2@example.com'
        m.user = usr
        meta.Session().add(m)
        meta.Session().commit()

        u = db.User.get_by_email(email='MAIN_email@example.com')
        assert usr.user_id == u.user_id
        assert usr.username == u.username

        u = db.User.get_by_email(email='main_email@example.com')
        assert usr.user_id == u.user_id
        assert usr.username == u.username

        u = db.User.get_by_email(email='main_email2@example.com')
        assert usr.user_id == u.user_id
        assert usr.username == u.username
        u = db.User.get_by_email(email='main_email3@example.com')
        assert u is None

        u = db.User.get_by_email(email='main_e%ail@example.com')
        assert u is None
        u = db.User.get_by_email(email='main_emai_@example.com')
        assert u is None

        UserModel().delete(usr.user_id)
        meta.Session().commit()


class TestUsers(base.TestController):

    def setup_method(self, method):
        self.u1 = UserModel().create_or_update(username='u1',
                                        password='qweqwe',
                                        email='u1@example.com',
                                        firstname='u1', lastname='u1')

    def teardown_method(self, method):
        perm = db.Permission.query().all()
        for p in perm:
            UserModel().revoke_perm(self.u1, p)

        UserModel().delete(self.u1)
        meta.Session().commit()
        meta.Session.remove()

    def test_add_perm(self):
        perm = db.Permission.query().all()[0]
        UserModel().grant_perm(self.u1, perm)
        meta.Session().commit()
        assert UserModel().has_perm(self.u1, perm) == True

    def test_has_perm(self):
        perm = db.Permission.query().all()
        for p in perm:
            has_p = UserModel().has_perm(self.u1, p)
            assert False == has_p

    def test_revoke_perm(self):
        perm = db.Permission.query().all()[0]
        UserModel().grant_perm(self.u1, perm)
        meta.Session().commit()
        assert UserModel().has_perm(self.u1, perm) == True

        # revoke
        UserModel().revoke_perm(self.u1, perm)
        meta.Session().commit()
        assert UserModel().has_perm(self.u1, perm) == False
