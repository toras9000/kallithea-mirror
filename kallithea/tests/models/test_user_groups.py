from kallithea.model import db, meta
from kallithea.model.user_group import UserGroupModel
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


class TestUserGroups(base.TestController):

    def teardown_method(self, method):
        # delete all groups
        for gr in db.UserGroup.query():
            fixture.destroy_user_group(gr)
        meta.Session().commit()

    @base.parametrize('pre_existing,regular_should_be,external_should_be,groups,expected', [
        ([], [], [], [], []),
        ([], ['regular'], [], [], ['regular']),  # no changes of regular
        (['some_other'], [], [], ['some_other'], []),   # not added to regular group
        ([], ['regular'], ['container'], ['container'], ['regular', 'container']),
        ([], ['regular'], [], ['container', 'container2'], ['regular', 'container', 'container2']),
        ([], ['regular'], ['other'], [], ['regular']),  # remove not used
        (['some_other'], ['regular'], ['other', 'container'], ['container', 'container2'], ['regular', 'container', 'container2']),
    ])
    def test_enforce_groups(self, pre_existing, regular_should_be,
                            external_should_be, groups, expected):
        # delete all groups
        for gr in db.UserGroup.query():
            fixture.destroy_user_group(gr)
        meta.Session().commit()

        user = db.User.get_by_username(base.TEST_USER_REGULAR_LOGIN)
        for gr in pre_existing:
            gr = fixture.create_user_group(gr)
        meta.Session().commit()

        # make sure use is just in those groups
        for gr in regular_should_be:
            gr = fixture.create_user_group(gr)
            meta.Session().commit()
            UserGroupModel().add_user_to_group(gr, user)
            meta.Session().commit()

        # now special external groups created by auth plugins
        for gr in external_should_be:
            gr = fixture.create_user_group(gr, user_group_data={'extern_type': 'container'})
            meta.Session().commit()
            UserGroupModel().add_user_to_group(gr, user)
            meta.Session().commit()

        UserGroupModel().enforce_groups(user, groups, 'container')
        meta.Session().commit()

        user = db.User.get_by_username(base.TEST_USER_REGULAR_LOGIN)
        in_groups = user.group_member
        assert sorted(expected) == sorted(x.users_group.users_group_name for x in in_groups)
