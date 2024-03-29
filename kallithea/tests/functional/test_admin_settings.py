# -*- coding: utf-8 -*-

from kallithea.model import db
from kallithea.tests import base
from kallithea.tests.fixture import Fixture


fixture = Fixture()


class TestAdminSettingsController(base.TestController):

    def test_index_main(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings'))

    def test_index_mapping(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_mapping'))

    def test_index_global(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_global'))

    def test_index_visual(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_visual'))

    def test_index_email(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_email'))

    def test_index_hooks(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_hooks'))
        response.mustcontain(no='.kallithea_')

    def test_create_custom_hook(self):
        self.log_user()
        response = self.app.post(base.url('admin_settings_hooks'),
                                params=dict(new_hook_ui_key='test_hooks_1',
                                            new_hook_ui_value='cd %s' % base.TESTS_TMP_PATH,
                                            _session_csrf_secret_token=self.session_csrf_secret_token()))

        self.checkSessionFlash(response, 'Added new hook')
        response = response.follow()
        response.mustcontain('test_hooks_1')
        response.mustcontain('cd %s' % base.TESTS_TMP_PATH)

        # test_edit_custom_hook
        response = self.app.post(base.url('admin_settings_hooks'),
                                params=dict(hook_ui_key='test_hooks_1',
                                            hook_ui_value='old_value_of_hook_1',
                                            hook_ui_value_new='new_value_of_hook_1',
                                            _session_csrf_secret_token=self.session_csrf_secret_token()))

        response = response.follow()
        response.mustcontain('test_hooks_1')
        response.mustcontain('new_value_of_hook_1')

        # test_add_existing_custom_hook
        response = self.app.post(base.url('admin_settings_hooks'),
                                params=dict(new_hook_ui_key='test_hooks_1',
                                            new_hook_ui_value='attempted_new_value',
                                            _session_csrf_secret_token=self.session_csrf_secret_token()))

        self.checkSessionFlash(response, 'Hook already exists')
        response = response.follow()
        response.mustcontain('test_hooks_1')
        response.mustcontain('new_value_of_hook_1')

    def test_create_custom_hook_delete(self):
        self.log_user()
        response = self.app.post(base.url('admin_settings_hooks'),
                                params=dict(new_hook_ui_key='test_hooks_2',
                                            new_hook_ui_value='cd %s2' % base.TESTS_TMP_PATH,
                                            _session_csrf_secret_token=self.session_csrf_secret_token()))

        self.checkSessionFlash(response, 'Added new hook')
        response = response.follow()
        response.mustcontain('test_hooks_2')
        response.mustcontain('cd %s2' % base.TESTS_TMP_PATH)

        hook_id = db.Ui.get_by_key('hooks', 'test_hooks_2').ui_id
        ## delete
        self.app.post(base.url('admin_settings_hooks'),
                        params=dict(hook_id=hook_id, _session_csrf_secret_token=self.session_csrf_secret_token()))
        response = self.app.get(base.url('admin_settings_hooks'))
        response.mustcontain(no=['test_hooks_2'])
        response.mustcontain(no=['cd %s2' % base.TESTS_TMP_PATH])

    def test_add_existing_builtin_hook(self):
        self.log_user()
        response = self.app.post(base.url('admin_settings_hooks'),
                                params=dict(new_hook_ui_key='changegroup.kallithea_update',
                                            new_hook_ui_value='attempted_new_value',
                                            _session_csrf_secret_token=self.session_csrf_secret_token()))

        self.checkSessionFlash(response, 'reserved for internal use')

    def test_index_search(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_search'))

    def test_index_system(self):
        self.log_user()
        response = self.app.get(base.url('admin_settings_system'))

    def test_ga_code_active(self):
        self.log_user()
        old_title = 'Kallithea'
        old_realm = 'Kallithea authentication'
        new_ga_code = 'ga-test-123456789'
        response = self.app.post(base.url('admin_settings_global'),
                        params=dict(title=old_title,
                                 realm=old_realm,
                                 ga_code=new_ga_code,
                                 captcha_private_key='',
                                 captcha_public_key='',
                                 _session_csrf_secret_token=self.session_csrf_secret_token(),
                                 ))

        self.checkSessionFlash(response, 'Updated application settings')

        assert db.Setting.get_app_settings()['ga_code'] == new_ga_code

        response = response.follow()
        response.mustcontain("""_gaq.push(['_setAccount', '%s']);""" % new_ga_code)

    def test_ga_code_inactive(self):
        self.log_user()
        old_title = 'Kallithea'
        old_realm = 'Kallithea authentication'
        new_ga_code = ''
        response = self.app.post(base.url('admin_settings_global'),
                        params=dict(title=old_title,
                                 realm=old_realm,
                                 ga_code=new_ga_code,
                                 captcha_private_key='',
                                 captcha_public_key='',
                                 _session_csrf_secret_token=self.session_csrf_secret_token(),
                                 ))

        self.checkSessionFlash(response, 'Updated application settings')
        assert db.Setting.get_app_settings()['ga_code'] == new_ga_code

        response = response.follow()
        response.mustcontain(no=["_gaq.push(['_setAccount', '%s']);" % new_ga_code])

    def test_captcha_activate(self):
        self.log_user()
        old_title = 'Kallithea'
        old_realm = 'Kallithea authentication'
        new_ga_code = ''
        response = self.app.post(base.url('admin_settings_global'),
                        params=dict(title=old_title,
                                 realm=old_realm,
                                 ga_code=new_ga_code,
                                 captcha_private_key='1234567890',
                                 captcha_public_key='1234567890',
                                 _session_csrf_secret_token=self.session_csrf_secret_token(),
                                 ))

        self.checkSessionFlash(response, 'Updated application settings')
        assert db.Setting.get_app_settings()['captcha_private_key'] == '1234567890'

        response = self.app.get(base.url('register'))
        response.mustcontain('captcha')

    def test_captcha_deactivate(self):
        self.log_user()
        old_title = 'Kallithea'
        old_realm = 'Kallithea authentication'
        new_ga_code = ''
        response = self.app.post(base.url('admin_settings_global'),
                        params=dict(title=old_title,
                                 realm=old_realm,
                                 ga_code=new_ga_code,
                                 captcha_private_key='',
                                 captcha_public_key='1234567890',
                                 _session_csrf_secret_token=self.session_csrf_secret_token(),
                                 ))

        self.checkSessionFlash(response, 'Updated application settings')
        assert db.Setting.get_app_settings()['captcha_private_key'] == ''

        response = self.app.get(base.url('register'))
        response.mustcontain(no=['captcha'])

    def test_title_change(self):
        self.log_user()
        old_title = 'Kallithea'
        new_title = old_title + '_changed'
        old_realm = 'Kallithea authentication'

        for new_title in ['Changed', 'Żółwik', old_title]:
            response = self.app.post(base.url('admin_settings_global'),
                        params=dict(title=new_title,
                                 realm=old_realm,
                                 ga_code='',
                                 captcha_private_key='',
                                 captcha_public_key='',
                                 _session_csrf_secret_token=self.session_csrf_secret_token(),
                                ))

            self.checkSessionFlash(response, 'Updated application settings')
            assert db.Setting.get_app_settings()['title'] == new_title

            response = response.follow()
            response.mustcontain("""<span class="branding">%s</span>""" % new_title)
