# -*- coding: utf-8 -*-
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
these are form validation classes
http://formencode.org/module-formencode.validators.html
for list of all available validators

we can create our own validators

The table below outlines the options which can be used in a schema in addition to the validators themselves
pre_validators          []     These validators will be applied before the schema
chained_validators      []     These validators will be applied after the schema
allow_extra_fields      False     If True, then it is not an error when keys that aren't associated with a validator are present
filter_extra_fields     False     If True, then keys that aren't associated with a validator are removed
if_key_missing          NoDefault If this is given, then any keys that aren't available but are expected will be replaced with this value (and then validated). This does not override a present .if_missing attribute on validators. NoDefault is a special FormEncode class to mean that no default values has been specified and therefore missing keys shouldn't take a default value.
ignore_key_missing      False     If True, then missing keys will be missing in the result, if the validator doesn't have .if_missing on it already


<name> = formencode.validators.<name of validator>
<name> must equal form name
list=[1,2,3,4,5]
for SELECT use formencode.All(OneOf(list), Int())

"""
import logging

import formencode
from formencode import All
from tg.i18n import ugettext as _

import kallithea
from kallithea.model import validators as v


log = logging.getLogger(__name__)


def LoginForm():
    class _LoginForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        username = v.UnicodeString(
            strip=True,
            min=1,
            not_empty=True,
            messages={
               'empty': _('Please enter a login'),
               'tooShort': _('Enter a value %(min)i characters long or more')}
        )

        password = v.UnicodeString(
            strip=False,
            min=3,
            not_empty=True,
            messages={
                'empty': _('Please enter a password'),
                'tooShort': _('Enter %(min)i characters or more')}
        )

        remember = v.StringBoolean(if_missing=False)

        chained_validators = [v.ValidAuth()]
    return _LoginForm


def PasswordChangeForm(username):
    class _PasswordChangeForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True

        current_password = v.ValidOldPassword(username)(not_empty=True)
        new_password = All(v.ValidPassword(), v.UnicodeString(strip=False, min=6))
        new_password_confirmation = All(v.ValidPassword(), v.UnicodeString(strip=False, min=6))

        chained_validators = [v.ValidPasswordsMatch('new_password',
                                                    'new_password_confirmation')]
    return _PasswordChangeForm


def UserForm(edit=False, old_data=None):
    old_data = old_data or {}

    class _UserForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        username = All(v.UnicodeString(strip=True, min=1, not_empty=True),
                       v.ValidUsername(edit, old_data))
        if edit:
            new_password = All(
                v.ValidPassword(),
                v.UnicodeString(strip=False, min=6, not_empty=False)
            )
            password_confirmation = All(
                v.ValidPassword(),
                v.UnicodeString(strip=False, min=6, not_empty=False),
            )
            admin = v.StringBoolean(if_missing=False)
            chained_validators = [v.ValidPasswordsMatch('new_password',
                                                        'password_confirmation')]
        else:
            password = All(
                v.ValidPassword(),
                v.UnicodeString(strip=False, min=6, not_empty=True)
            )
            password_confirmation = All(
                v.ValidPassword(),
                v.UnicodeString(strip=False, min=6, not_empty=False)
            )
            chained_validators = [v.ValidPasswordsMatch('password',
                                                        'password_confirmation')]

        active = v.StringBoolean(if_missing=False)
        firstname = v.UnicodeString(strip=True, min=1, not_empty=False)
        lastname = v.UnicodeString(strip=True, min=1, not_empty=False)
        email = All(v.Email(not_empty=True), v.UniqSystemEmail(old_data))
        extern_name = v.UnicodeString(strip=True, if_missing=None)
        extern_type = v.UnicodeString(strip=True, if_missing=None)
    return _UserForm


def UserGroupForm(edit=False, old_data=None, available_members=None):
    old_data = old_data or {}
    available_members = available_members or []

    class _UserGroupForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True

        users_group_name = All(
            v.UnicodeString(strip=True, min=1, not_empty=True),
            v.ValidUserGroup(edit, old_data)
        )
        user_group_description = v.UnicodeString(strip=True, min=1,
                                                 not_empty=False)

        users_group_active = v.StringBoolean(if_missing=False)

        if edit:
            users_group_members = v.OneOf(
                available_members, hideList=False, testValueList=True,
                if_missing=None, not_empty=False
            )

    return _UserGroupForm


def RepoGroupForm(edit=False, old_data=None, repo_groups=None,
                   can_create_in_root=False):
    old_data = old_data or {}
    repo_groups = repo_groups or []
    repo_group_ids = [rg[0] for rg in repo_groups]

    class _RepoGroupForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False

        group_name = All(v.UnicodeString(strip=True, min=1, not_empty=True),
                         v.SlugifyName(),
                         v.ValidRegex(msg=_('Name must not contain only digits'))(r'(?!^\d+$)^.+$'))
        group_description = v.UnicodeString(strip=True, min=1,
                                            not_empty=False)
        group_copy_permissions = v.StringBoolean(if_missing=False)

        if edit:
            owner = All(v.UnicodeString(not_empty=True), v.ValidRepoUser())
            # FIXME: do a special check that we cannot move a group to one of
            # its children
            pass

        parent_group_id = All(v.CanCreateGroup(can_create_in_root),
                              v.OneOf(repo_group_ids, hideList=False,
                                      testValueList=True,
                                      if_missing=None, not_empty=True),
                              v.Int(min=-1, not_empty=True))
        chained_validators = [v.ValidRepoGroup(edit, old_data)]

    return _RepoGroupForm


def RegisterForm(edit=False, old_data=None):
    class _RegisterForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        username = All(
            v.ValidUsername(edit, old_data),
            v.UnicodeString(strip=True, min=1, not_empty=True)
        )
        password = All(
            v.ValidPassword(),
            v.UnicodeString(strip=False, min=6, not_empty=True)
        )
        password_confirmation = All(
            v.ValidPassword(),
            v.UnicodeString(strip=False, min=6, not_empty=True)
        )
        active = v.StringBoolean(if_missing=False)
        firstname = v.UnicodeString(strip=True, min=1, not_empty=False)
        lastname = v.UnicodeString(strip=True, min=1, not_empty=False)
        email = All(v.Email(not_empty=True), v.UniqSystemEmail(old_data))

        chained_validators = [v.ValidPasswordsMatch('password',
                                                    'password_confirmation')]

    return _RegisterForm


def PasswordResetRequestForm():
    class _PasswordResetRequestForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        email = v.Email(not_empty=True)
    return _PasswordResetRequestForm


def PasswordResetConfirmationForm():
    class _PasswordResetConfirmationForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True

        email = v.UnicodeString(strip=True, not_empty=True)
        timestamp = v.Number(strip=True, not_empty=True)
        token = v.UnicodeString(strip=True, not_empty=True)
        password = All(v.ValidPassword(), v.UnicodeString(strip=False, min=6))
        password_confirm = All(v.ValidPassword(), v.UnicodeString(strip=False, min=6))

        chained_validators = [v.ValidPasswordsMatch('password',
                                                    'password_confirm')]
    return _PasswordResetConfirmationForm


def RepoForm(edit=False, old_data=None, supported_backends=kallithea.BACKENDS,
             repo_groups=None, landing_revs=None):
    old_data = old_data or {}
    repo_groups = repo_groups or []
    landing_revs = landing_revs or []
    repo_group_ids = [rg[0] for rg in repo_groups]

    class _RepoForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        repo_name = All(v.UnicodeString(strip=True, min=1, not_empty=True),
                        v.SlugifyName())
        repo_group = All(v.CanWriteGroup(old_data),
                         v.OneOf(repo_group_ids, hideList=True),
                         v.Int(min=-1, not_empty=True))
        repo_type = v.OneOf(supported_backends, required=False,
                            if_missing=old_data.get('repo_type'))
        repo_description = v.UnicodeString(strip=True, min=1, not_empty=False)
        repo_private = v.StringBoolean(if_missing=False)
        repo_landing_rev = v.OneOf(landing_revs, hideList=True)
        repo_copy_permissions = v.StringBoolean(if_missing=False)
        clone_uri = All(v.UnicodeString(strip=True, min=1, not_empty=False))

        repo_enable_statistics = v.StringBoolean(if_missing=False)
        repo_enable_downloads = v.StringBoolean(if_missing=False)

        if edit:
            owner = All(v.UnicodeString(not_empty=True), v.ValidRepoUser())
            # Not a real field - just for reference for validation:
            # clone_uri_hidden = v.UnicodeString(if_missing='')

        chained_validators = [v.ValidCloneUri(),
                              v.ValidRepoName(edit, old_data)]
    return _RepoForm


def RepoPermsForm():
    class _RepoPermsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        chained_validators = [v.ValidPerms(type_='repo')]
    return _RepoPermsForm


def RepoGroupPermsForm(valid_recursive_choices):
    class _RepoGroupPermsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        recursive = v.OneOf(valid_recursive_choices)
        chained_validators = [v.ValidPerms(type_='repo_group')]
    return _RepoGroupPermsForm


def UserGroupPermsForm():
    class _UserPermsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        chained_validators = [v.ValidPerms(type_='user_group')]
    return _UserPermsForm


def RepoFieldForm():
    class _RepoFieldForm(formencode.Schema):
        filter_extra_fields = True
        allow_extra_fields = True

        new_field_key = All(v.FieldKey(),
                            v.UnicodeString(strip=True, min=3, not_empty=True))
        new_field_value = v.UnicodeString(not_empty=False, if_missing='')
        new_field_type = v.OneOf(['str', 'unicode', 'list', 'tuple'],
                                 if_missing='str')
        new_field_label = v.UnicodeString(not_empty=False)
        new_field_desc = v.UnicodeString(not_empty=False)

    return _RepoFieldForm


def RepoForkForm(edit=False, old_data=None, supported_backends=kallithea.BACKENDS,
                 repo_groups=None, landing_revs=None):
    old_data = old_data or {}
    repo_groups = repo_groups or []
    landing_revs = landing_revs or []
    repo_group_ids = [rg[0] for rg in repo_groups]

    class _RepoForkForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        repo_name = All(v.UnicodeString(strip=True, min=1, not_empty=True),
                        v.SlugifyName())
        repo_group = All(v.CanWriteGroup(),
                         v.OneOf(repo_group_ids, hideList=True),
                         v.Int(min=-1, not_empty=True))
        repo_type = All(v.ValidForkType(old_data), v.OneOf(supported_backends))
        description = v.UnicodeString(strip=True, min=1, not_empty=True)
        private = v.StringBoolean(if_missing=False)
        copy_permissions = v.StringBoolean(if_missing=False)
        update_after_clone = v.StringBoolean(if_missing=False)
        fork_parent_id = v.UnicodeString()
        chained_validators = [v.ValidForkName(edit, old_data)]
        landing_rev = v.OneOf(landing_revs, hideList=True)

    return _RepoForkForm


def ApplicationSettingsForm():
    class _ApplicationSettingsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        title = v.UnicodeString(strip=True, not_empty=False)
        realm = v.UnicodeString(strip=True, min=1, not_empty=True)
        ga_code = v.UnicodeString(strip=True, min=1, not_empty=False)
        captcha_public_key = v.UnicodeString(strip=True, min=1, not_empty=False)
        captcha_private_key = v.UnicodeString(strip=True, min=1, not_empty=False)

    return _ApplicationSettingsForm


def ApplicationVisualisationForm():
    class _ApplicationVisualisationForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        show_public_icon = v.StringBoolean(if_missing=False)
        show_private_icon = v.StringBoolean(if_missing=False)
        stylify_metalabels = v.StringBoolean(if_missing=False)

        repository_fields = v.StringBoolean(if_missing=False)
        lightweight_journal = v.StringBoolean(if_missing=False)
        dashboard_items = v.Int(min=5, not_empty=True)
        admin_grid_items = v.Int(min=5, not_empty=True)
        show_version = v.StringBoolean(if_missing=False)
        use_gravatar = v.StringBoolean(if_missing=False)
        gravatar_url = v.UnicodeString(min=3)
        clone_uri_tmpl = v.UnicodeString(min=3)
        clone_ssh_tmpl = v.UnicodeString()

    return _ApplicationVisualisationForm


def ApplicationUiSettingsForm():
    class _ApplicationUiSettingsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = False
        paths_root_path = All(
            v.ValidPath(),
            v.UnicodeString(strip=True, min=1, not_empty=True)
        )
        hooks_changegroup_kallithea_update = v.StringBoolean(if_missing=False)
        hooks_changegroup_kallithea_repo_size = v.StringBoolean(if_missing=False)

        extensions_largefiles = v.StringBoolean(if_missing=False)
        extensions_hggit = v.StringBoolean(if_missing=False)

    return _ApplicationUiSettingsForm


def DefaultPermissionsForm(repo_perms_choices, group_perms_choices,
                           user_group_perms_choices, create_choices,
                           user_group_create_choices, fork_choices,
                           register_choices, extern_activate_choices):
    class _DefaultPermissionsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        overwrite_default_repo = v.StringBoolean(if_missing=False)
        overwrite_default_group = v.StringBoolean(if_missing=False)
        overwrite_default_user_group = v.StringBoolean(if_missing=False)
        anonymous = v.StringBoolean(if_missing=False)
        default_repo_perm = v.OneOf(repo_perms_choices)
        default_group_perm = v.OneOf(group_perms_choices)
        default_user_group_perm = v.OneOf(user_group_perms_choices)

        default_repo_create = v.OneOf(create_choices)
        default_user_group_create = v.OneOf(user_group_create_choices)
        default_fork = v.OneOf(fork_choices)

        default_register = v.OneOf(register_choices)
        default_extern_activate = v.OneOf(extern_activate_choices)
    return _DefaultPermissionsForm


def CustomDefaultPermissionsForm():
    class _CustomDefaultPermissionsForm(formencode.Schema):
        filter_extra_fields = True
        allow_extra_fields = True

        create_repo_perm = v.StringBoolean(if_missing=False)
        create_user_group_perm = v.StringBoolean(if_missing=False)
        #create_repo_group_perm Impl. later

        fork_repo_perm = v.StringBoolean(if_missing=False)

    return _CustomDefaultPermissionsForm


def DefaultsForm(edit=False, old_data=None, supported_backends=kallithea.BACKENDS):
    class _DefaultsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        default_repo_type = v.OneOf(supported_backends)
        default_repo_private = v.StringBoolean(if_missing=False)
        default_repo_enable_statistics = v.StringBoolean(if_missing=False)
        default_repo_enable_downloads = v.StringBoolean(if_missing=False)

    return _DefaultsForm


def AuthSettingsForm(current_active_modules):
    class _AuthSettingsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        auth_plugins = All(v.ValidAuthPlugins(),
                           v.UniqueListFromString()(not_empty=True))

        def __init__(self, *args, **kwargs):
            # The auth plugins tell us what form validators they use
            if current_active_modules:
                import kallithea.lib.auth_modules
                from kallithea.lib.auth_modules import LazyFormencode
                for module in current_active_modules:
                    plugin = kallithea.lib.auth_modules.loadplugin(module)
                    plugin_name = plugin.name
                    for sv in plugin.plugin_settings():
                        newk = "auth_%s_%s" % (plugin_name, sv["name"])
                        # can be a LazyFormencode object from plugin settings
                        validator = sv["validator"]
                        if isinstance(validator, LazyFormencode):
                            validator = validator()
                        # init all lazy validators from formencode.All
                        if isinstance(validator, All):
                            init_validators = []
                            for validator in validator.validators:
                                if isinstance(validator, LazyFormencode):
                                    validator = validator()
                                init_validators.append(validator)
                            validator.validators = init_validators

                        self.add_field(newk, validator)
            formencode.Schema.__init__(self, *args, **kwargs)

    return _AuthSettingsForm


def LdapSettingsForm(tls_reqcert_choices, search_scope_choices,
                     tls_kind_choices):
    class _LdapSettingsForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True
        #pre_validators = [LdapLibValidator]
        ldap_active = v.StringBoolean(if_missing=False)
        ldap_host = v.UnicodeString(strip=True,)
        ldap_port = v.Number(strip=True,)
        ldap_tls_kind = v.OneOf(tls_kind_choices)
        ldap_tls_reqcert = v.OneOf(tls_reqcert_choices)
        ldap_dn_user = v.UnicodeString(strip=True,)
        ldap_dn_pass = v.UnicodeString(strip=True,)
        ldap_base_dn = v.UnicodeString(strip=True,)
        ldap_filter = v.UnicodeString(strip=True,)
        ldap_search_scope = v.OneOf(search_scope_choices)
        ldap_attr_login = v.AttrLoginValidator()(not_empty=True)
        ldap_attr_firstname = v.UnicodeString(strip=True,)
        ldap_attr_lastname = v.UnicodeString(strip=True,)
        ldap_attr_email = v.UnicodeString(strip=True,)

    return _LdapSettingsForm


def UserExtraEmailForm():
    class _UserExtraEmailForm(formencode.Schema):
        email = All(v.UniqSystemEmail(), v.Email(not_empty=True))
    return _UserExtraEmailForm


def UserExtraIpForm():
    class _UserExtraIpForm(formencode.Schema):
        ip = v.ValidIp()(not_empty=True)
    return _UserExtraIpForm


def PullRequestForm(repo_id):
    class _PullRequestForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True

        org_repo = v.UnicodeString(strip=True, required=True)
        org_ref = v.UnicodeString(strip=True, required=True)
        other_repo = v.UnicodeString(strip=True, required=True)
        other_ref = v.UnicodeString(strip=True, required=True)

        pullrequest_title = v.UnicodeString(strip=True, required=True)
        pullrequest_desc = v.UnicodeString(strip=True, required=False)

    return _PullRequestForm


def PullRequestPostForm():
    class _PullRequestPostForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True

        pullrequest_title = v.UnicodeString(strip=True, required=True)
        pullrequest_desc = v.UnicodeString(strip=True, required=False)
        org_review_members = v.Set()
        review_members = v.Set()
        updaterev = v.UnicodeString(strip=True, required=False, if_missing=None)
        owner = All(v.UnicodeString(strip=True, required=True),
                    v.ValidRepoUser())

    return _PullRequestPostForm


def GistForm(lifetime_options):
    class _GistForm(formencode.Schema):
        allow_extra_fields = True
        filter_extra_fields = True

        filename = All(v.BasePath()(),
                       v.UnicodeString(strip=True, required=False))
        description = v.UnicodeString(required=False, if_missing='')
        lifetime = v.OneOf(lifetime_options)
        mimetype = v.UnicodeString(required=False, if_missing=None)
        content = v.UnicodeString(required=True, not_empty=True)
        public = v.UnicodeString(required=False, if_missing='')
        private = v.UnicodeString(required=False, if_missing='')

    return _GistForm
