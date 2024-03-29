import datetime

from kallithea.tests import base


class TestJournalController(base.TestController):

    def test_index(self):
        self.log_user()
        response = self.app.get(base.url(controller='journal', action='index'))

        response.mustcontain("""<h4>%s</h4>""" % datetime.date.today())

    def test_stop_following_repository(self):
        session = self.log_user()
#        usr = Session().query(User).filter(db.User.username == TEST_USER_ADMIN_LOGIN).one()
#        repo = Session().query(db.Repository).filter(db.Repository.repo_name == HG_REPO).one()
#
#        followings = Session().query(db.UserFollowing) \
#            .filter(db.UserFollowing.user == usr) \
#            .filter(db.UserFollowing.follows_repository == repo).all()
#
#        assert len(followings) == 1, 'Not following any repository'
#
#        response = self.app.post(base.url(controller='journal',
#                                     action='toggle_following'),
#                                     {'follows_repository_id':repo.repo_id})

    def test_start_following_repository(self):
        self.log_user()
        response = self.app.get(base.url(controller='journal', action='index'),)

    def test_public_journal_atom(self):
        self.log_user()
        response = self.app.get(base.url(controller='journal', action='public_journal_atom'),)

    def test_public_journal_rss(self):
        self.log_user()
        response = self.app.get(base.url(controller='journal', action='public_journal_rss'),)
