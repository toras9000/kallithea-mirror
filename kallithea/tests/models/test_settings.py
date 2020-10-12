from kallithea.model import db, meta


name = 'spam-setting-name'


def test_passing_list_setting_value_results_in_string_valued_setting():
    assert db.Setting.get_by_name(name) is None
    setting = db.Setting.create_or_update(name, ['spam', 'eggs'])
    meta.Session().flush() # must flush so we can delete it below
    try:
        assert db.Setting.get_by_name(name) is not None
        # Quirk: list value is stringified.
        assert db.Setting.get_by_name(name).app_settings_value \
               == "['spam', 'eggs']"
        assert db.Setting.get_by_name(name).app_settings_type == 'unicode'
    finally:
        meta.Session().delete(setting)


def test_list_valued_setting_creation_requires_manual_value_formatting():
    assert db.Setting.get_by_name(name) is None
    # Quirk: need manual formatting of list setting value.
    setting = db.Setting.create_or_update(name, 'spam,eggs', type='list')
    meta.Session().flush() # must flush so we can delete it below
    try:
        assert setting.app_settings_value == ['spam', 'eggs']
    finally:
        meta.Session().delete(setting)


def test_list_valued_setting_update():
    assert db.Setting.get_by_name(name) is None
    setting = db.Setting.create_or_update(name, 'spam', type='list')
    meta.Session().flush() # must flush so we can delete it below
    try:
        assert setting.app_settings_value == ['spam']
        # Assign back setting value.
        setting.app_settings_value = setting.app_settings_value
        # Quirk: value is stringified on write and listified on read.
        assert setting.app_settings_value == ["['spam']"]
        setting.app_settings_value = setting.app_settings_value
        assert setting.app_settings_value == ["[\"['spam']\"]"]
    finally:
        meta.Session().delete(setting)
