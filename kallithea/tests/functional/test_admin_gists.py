from kallithea.model import db, meta
from kallithea.model.gist import GistModel
from kallithea.tests import base


def _create_gist(f_name, content='some gist', lifetime=-1,
                 description='gist-desc', gist_type='public',
                 owner=base.TEST_USER_ADMIN_LOGIN):
    gist_mapping = {
        f_name: {'content': content}
    }
    owner = db.User.get_by_username(owner)
    gist = GistModel().create(description, owner=owner, ip_addr=base.IP_ADDR,
                       gist_mapping=gist_mapping, gist_type=gist_type,
                       lifetime=lifetime)
    meta.Session().commit()
    return gist


class TestGistsController(base.TestController):

    def teardown_method(self, method):
        for g in db.Gist.query():
            GistModel().delete(g)
        meta.Session().commit()

    def test_index(self):
        self.log_user()
        response = self.app.get(base.url('gists'))
        # Test response...
        response.mustcontain('There are no gists yet')

        g1 = _create_gist('gist1').gist_access_id
        g2 = _create_gist('gist2', lifetime=1400).gist_access_id
        g3 = _create_gist('gist3', description='gist3-desc').gist_access_id
        g4 = _create_gist('gist4', gist_type='private').gist_access_id
        response = self.app.get(base.url('gists'))
        # Test response...
        response.mustcontain('gist: %s' % g1)
        response.mustcontain('gist: %s' % g2)
        response.mustcontain('Expires: in 23 hours')  # we don't care about the end
        response.mustcontain('gist: %s' % g3)
        response.mustcontain('gist3-desc')
        response.mustcontain(no=['gist: %s' % g4])

    def test_index_private_gists(self):
        self.log_user()
        gist = _create_gist('gist5', gist_type='private')
        response = self.app.get(base.url('gists', private=1))
        # Test response...

        # and privates
        response.mustcontain('gist: %s' % gist.gist_access_id)

    def test_create_missing_description(self):
        self.log_user()
        response = self.app.post(base.url('gists'),
                                 params={'lifetime': -1, '_session_csrf_secret_token': self.session_csrf_secret_token()},
                                 status=200)

        response.mustcontain('Missing value')

    def test_create(self):
        self.log_user()
        response = self.app.post(base.url('gists'),
                                 params={'lifetime': -1,
                                         'content': 'gist test',
                                         'filename': 'foo',
                                         'public': 'public',
                                         '_session_csrf_secret_token': self.session_csrf_secret_token()},
                                 status=302)
        response = response.follow()
        response.mustcontain('added file: foo')
        response.mustcontain('gist test')
        response.mustcontain('<div class="label label-success">Public Gist</div>')

    def test_create_with_path_with_dirs(self):
        self.log_user()
        response = self.app.post(base.url('gists'),
                                 params={'lifetime': -1,
                                         'content': 'gist test',
                                         'filename': '/home/foo',
                                         'public': 'public',
                                         '_session_csrf_secret_token': self.session_csrf_secret_token()},
                                 status=200)
        response.mustcontain('Filename cannot be inside a directory')

    def test_access_expired_gist(self):
        self.log_user()
        gist = _create_gist('never-see-me')
        gist.gist_expires = 0  # 1970
        meta.Session().commit()

        response = self.app.get(base.url('gist', gist_id=gist.gist_access_id), status=404)

    def test_create_private(self):
        self.log_user()
        response = self.app.post(base.url('gists'),
                                 params={'lifetime': -1,
                                         'content': 'private gist test',
                                         'filename': 'private-foo',
                                         'private': 'private',
                                         '_session_csrf_secret_token': self.session_csrf_secret_token()},
                                 status=302)
        response = response.follow()
        response.mustcontain('added file: private-foo<')
        response.mustcontain('private gist test')
        response.mustcontain('<div class="label label-warning">Private Gist</div>')

    def test_create_with_description(self):
        self.log_user()
        response = self.app.post(base.url('gists'),
                                 params={'lifetime': -1,
                                         'content': 'gist test',
                                         'filename': 'foo-desc',
                                         'description': 'gist-desc',
                                         'public': 'public',
                                         '_session_csrf_secret_token': self.session_csrf_secret_token()},
                                 status=302)
        response = response.follow()
        response.mustcontain('added file: foo-desc')
        response.mustcontain('gist test')
        response.mustcontain('gist-desc')
        response.mustcontain('<div class="label label-success">Public Gist</div>')

    def test_new(self):
        self.log_user()
        response = self.app.get(base.url('new_gist'))

    def test_delete(self):
        self.log_user()
        gist = _create_gist('delete-me')
        response = self.app.post(base.url('gist_delete', gist_id=gist.gist_id),
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})

    def test_delete_normal_user_his_gist(self):
        self.log_user(base.TEST_USER_REGULAR_LOGIN, base.TEST_USER_REGULAR_PASS)
        gist = _create_gist('delete-me', owner=base.TEST_USER_REGULAR_LOGIN)
        response = self.app.post(base.url('gist_delete', gist_id=gist.gist_id),
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})

    def test_delete_normal_user_not_his_own_gist(self):
        self.log_user(base.TEST_USER_REGULAR_LOGIN, base.TEST_USER_REGULAR_PASS)
        gist = _create_gist('delete-me')
        response = self.app.post(base.url('gist_delete', gist_id=gist.gist_id), status=403,
            params={'_session_csrf_secret_token': self.session_csrf_secret_token()})

    def test_show(self):
        gist = _create_gist('gist-show-me')
        response = self.app.get(base.url('gist', gist_id=gist.gist_access_id))
        response.mustcontain('added file: gist-show-me<')
        response.mustcontain('%s - created' % base.TEST_USER_ADMIN_LOGIN)
        response.mustcontain('gist-desc')
        response.mustcontain('<div class="label label-success">Public Gist</div>')

    def test_show_as_raw(self):
        gist = _create_gist('gist-show-me', content='GIST CONTENT')
        response = self.app.get(base.url('formatted_gist',
                                    gist_id=gist.gist_access_id, format='raw'))
        assert response.body == b'GIST CONTENT'

    def test_show_as_raw_individual_file(self):
        gist = _create_gist('gist-show-me-raw', content='GIST BODY')
        response = self.app.get(base.url('formatted_gist_file',
                                    gist_id=gist.gist_access_id, format='raw',
                                    revision='tip', f_path='gist-show-me-raw'))
        assert response.body == b'GIST BODY'

    def test_edit(self):
        gist = _create_gist('gist-edit')
        response = self.app.get(base.url('edit_gist', gist_id=gist.gist_access_id), status=302)
        assert 'login' in response.location

        self.log_user(base.TEST_USER_REGULAR_LOGIN, base.TEST_USER_REGULAR_PASS)
        response = self.app.get(base.url('edit_gist', gist_id=gist.gist_access_id))

        # FIXME actually test editing the gist
