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
Set of generic validators
"""

import logging
import os
import re
from collections import defaultdict

import formencode
import ipaddr
import sqlalchemy
from formencode.validators import CIDR, Bool, Email, FancyValidator, Int, IPAddress, NotEmpty, Number, OneOf, Regex, Set, String, StringBoolean, UnicodeString
from sqlalchemy import func
from tg.i18n import ugettext as _

import kallithea
from kallithea.lib import auth
from kallithea.lib.compat import OrderedSet
from kallithea.lib.exceptions import InvalidCloneUriException, LdapImportError
from kallithea.lib.utils import is_valid_repo_uri
from kallithea.lib.utils2 import asbool, aslist, repo_name_slug
from kallithea.model import db


# silence warnings and pylint
UnicodeString, OneOf, Int, Number, Regex, Email, Bool, StringBoolean, Set, \
    NotEmpty, IPAddress, CIDR, String, FancyValidator

log = logging.getLogger(__name__)


def UniqueListFromString():
    class _UniqueListFromString(formencode.FancyValidator):
        """
        Split value on ',' and make unique while preserving order
        """
        messages = dict(
            empty=_('Value cannot be an empty list'),
            missing_value=_('Value cannot be an empty list'),
        )

        def _convert_to_python(self, value, state):
            value = aslist(value, ',')
            seen = set()
            return [c for c in value if not (c in seen or seen.add(c))]

        def empty_value(self, value):
            return []

    return _UniqueListFromString


def ValidUsername(edit=False, old_data=None):
    old_data = old_data or {}

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'username_exists': _('Username "%(username)s" already exists'),
            'system_invalid_username':
                _('Username "%(username)s" cannot be used'),
            'invalid_username':
                _('Username may only contain alphanumeric characters '
                  'underscores, periods or dashes and must begin with an '
                  'alphanumeric character or underscore')
        }

        def _validate_python(self, value, state):
            if value in ['default', 'new_user']:
                msg = self.message('system_invalid_username', state, username=value)
                raise formencode.Invalid(msg, value, state)
            # check if user is unique
            old_un = None
            if edit:
                old_un = db.User.get(old_data.get('user_id')).username

            if old_un != value or not edit:
                if db.User.get_by_username(value, case_insensitive=True):
                    msg = self.message('username_exists', state, username=value)
                    raise formencode.Invalid(msg, value, state)

            if re.match(r'^[a-zA-Z0-9\_]{1}[a-zA-Z0-9\-\_\.]*$', value) is None:
                msg = self.message('invalid_username', state)
                raise formencode.Invalid(msg, value, state)
    return _validator


def ValidRegex(msg=None):
    class _validator(formencode.validators.Regex):
        messages = dict(invalid=msg or _('The input is not valid'))
    return _validator


def ValidRepoUser():
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_username': _('Username %(username)s is not valid')
        }

        def _validate_python(self, value, state):
            try:
                db.User.query().filter(db.User.active == True) \
                    .filter(db.User.username == value).one()
            except sqlalchemy.exc.InvalidRequestError: # NoResultFound/MultipleResultsFound
                msg = self.message('invalid_username', state, username=value)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(username=msg)
                )

    return _validator


def ValidUserGroup(edit=False, old_data=None):
    old_data = old_data or {}

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_group': _('Invalid user group name'),
            'group_exist': _('User group "%(usergroup)s" already exists'),
            'invalid_usergroup_name':
                _('user group name may only contain alphanumeric '
                  'characters underscores, periods or dashes and must begin '
                  'with alphanumeric character')
        }

        def _validate_python(self, value, state):
            if value in ['default']:
                msg = self.message('invalid_group', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(users_group_name=msg)
                )
            # check if group is unique
            old_ugname = None
            if edit:
                old_id = old_data.get('users_group_id')
                old_ugname = db.UserGroup.get(old_id).users_group_name

            if old_ugname != value or not edit:
                is_existing_group = db.UserGroup.get_by_group_name(value,
                                                        case_insensitive=True)
                if is_existing_group:
                    msg = self.message('group_exist', state, usergroup=value)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(users_group_name=msg)
                    )

            if re.match(r'^[a-zA-Z0-9]{1}[a-zA-Z0-9\-\_\.]+$', value) is None:
                msg = self.message('invalid_usergroup_name', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(users_group_name=msg)
                )

    return _validator


def ValidRepoGroup(edit=False, old_data=None):
    old_data = old_data or {}

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'parent_group_id': _('Cannot assign this group as parent'),
            'group_exists': _('Group "%(group_name)s" already exists'),
            'repo_exists':
                _('Repository with name "%(group_name)s" already exists')
        }

        def _validate_python(self, value, state):
            # TODO WRITE VALIDATIONS
            group_name = value.get('group_name')
            parent_group_id = value.get('parent_group_id')

            # slugify repo group just in case :)
            slug = repo_name_slug(group_name)

            # check for parent of self
            if edit and parent_group_id and old_data['group_id'] == parent_group_id:
                msg = self.message('parent_group_id', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(parent_group_id=msg)
                )

            old_gname = None
            if edit:
                old_gname = db.RepoGroup.get(old_data.get('group_id')).group_name

            if old_gname != group_name or not edit:

                # check group
                gr = db.RepoGroup.query() \
                      .filter(func.lower(db.RepoGroup.group_name) == func.lower(slug)) \
                      .filter(db.RepoGroup.parent_group_id == parent_group_id) \
                      .scalar()
                if gr is not None:
                    msg = self.message('group_exists', state, group_name=slug)
                    raise formencode.Invalid(msg, value, state,
                            error_dict=dict(group_name=msg)
                    )

                # check for same repo
                repo = db.Repository.query() \
                      .filter(func.lower(db.Repository.repo_name) == func.lower(slug)) \
                      .scalar()
                if repo is not None:
                    msg = self.message('repo_exists', state, group_name=slug)
                    raise formencode.Invalid(msg, value, state,
                            error_dict=dict(group_name=msg)
                    )

    return _validator


def ValidPassword():
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_password':
                _('Invalid characters (non-ascii) in password')
        }

        def _validate_python(self, value, state):
            try:
                (value or '').encode('ascii')
            except UnicodeError:
                msg = self.message('invalid_password', state)
                raise formencode.Invalid(msg, value, state,)
    return _validator


def ValidOldPassword(username):
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_password': _('Invalid old password')
        }

        def _validate_python(self, value, state):
            from kallithea.lib import auth_modules
            if auth_modules.authenticate(username, value, '') is None:
                msg = self.message('invalid_password', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(current_password=msg)
                )
    return _validator


def ValidPasswordsMatch(password_field, password_confirmation_field):
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'password_mismatch': _('Passwords do not match'),
        }

        def _validate_python(self, value, state):
            if value.get(password_field) != value[password_confirmation_field]:
                msg = self.message('password_mismatch', state)
                raise formencode.Invalid(msg, value, state,
                     error_dict={password_field: msg, password_confirmation_field: msg}
                )
    return _validator


def ValidAuth():
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_auth': _('Invalid username or password'),
        }

        def _validate_python(self, value, state):
            from kallithea.lib import auth_modules

            password = value['password']
            username = value['username']

            # authenticate returns unused dict but has called
            # plugin._authenticate which has create_or_update'ed the username user in db
            if auth_modules.authenticate(username, password) is None:
                user = db.User.get_by_username_or_email(username)
                if user and not user.active:
                    log.warning('user %s is disabled', username)
                    msg = self.message('invalid_auth', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(username=' ', password=msg)
                    )
                else:
                    log.warning('user %s failed to authenticate', username)
                    msg = self.message('invalid_auth', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(username=' ', password=msg)
                    )
    return _validator


def ValidRepoName(edit=False, old_data=None):
    old_data = old_data or {}

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_repo_name':
                _('Repository name %(repo)s is not allowed'),
            'repository_exists':
                _('Repository named %(repo)s already exists'),
            'repository_in_group_exists': _('Repository "%(repo)s" already '
                                            'exists in group "%(group)s"'),
            'same_group_exists': _('Repository group with name "%(repo)s" '
                                   'already exists')
        }

        def _convert_to_python(self, value, state):
            repo_name = repo_name_slug(value.get('repo_name', ''))
            repo_group = value.get('repo_group')
            if repo_group:
                gr = db.RepoGroup.get(repo_group)
                group_path = gr.full_path
                group_name = gr.group_name
                # value needs to be aware of group name in order to check
                # db key This is an actual just the name to store in the
                # database
                repo_name_full = group_path + kallithea.URL_SEP + repo_name
            else:
                group_name = group_path = ''
                repo_name_full = repo_name

            value['repo_name'] = repo_name
            value['repo_name_full'] = repo_name_full
            value['group_path'] = group_path
            value['group_name'] = group_name
            return value

        def _validate_python(self, value, state):
            repo_name = value.get('repo_name')
            repo_name_full = value.get('repo_name_full')
            group_path = value.get('group_path')
            group_name = value.get('group_name')

            if repo_name in [kallithea.ADMIN_PREFIX, '']:
                msg = self.message('invalid_repo_name', state, repo=repo_name)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(repo_name=msg)
                )

            rename = old_data.get('repo_name') != repo_name_full
            create = not edit
            if rename or create:
                repo = db.Repository.get_by_repo_name(repo_name_full, case_insensitive=True)
                repo_group = db.RepoGroup.get_by_group_name(repo_name_full, case_insensitive=True)
                if group_path != '':
                    if repo is not None:
                        msg = self.message('repository_in_group_exists', state,
                                repo=repo.repo_name, group=group_name)
                        raise formencode.Invalid(msg, value, state,
                            error_dict=dict(repo_name=msg)
                        )
                elif repo_group is not None:
                    msg = self.message('same_group_exists', state,
                            repo=repo_name)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(repo_name=msg)
                    )
                elif repo is not None:
                    msg = self.message('repository_exists', state,
                            repo=repo.repo_name)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(repo_name=msg)
                    )
            return value
    return _validator


def ValidForkName(*args, **kwargs):
    return ValidRepoName(*args, **kwargs)


def SlugifyName():
    class _validator(formencode.validators.FancyValidator):

        def _convert_to_python(self, value, state):
            return repo_name_slug(value)

        def _validate_python(self, value, state):
            pass

    return _validator


def ValidCloneUri():
    from kallithea.lib.utils import make_ui

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'clone_uri': _('Invalid repository URL'),
            'invalid_clone_uri': _('Invalid repository URL. It must be a '
                                   'valid http, https, or ssh URL'),
        }

        def _validate_python(self, value, state):
            repo_type = value.get('repo_type')
            url = value.get('clone_uri')

            if url and url != value.get('clone_uri_hidden'):
                try:
                    is_valid_repo_uri(repo_type, url, make_ui())
                except InvalidCloneUriException as e:
                    log.warning('validation of clone URL %r failed: %s', url, e)
                    msg = self.message('clone_uri', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(clone_uri=msg)
                    )
    return _validator


def ValidForkType(old_data=None):
    old_data = old_data or {}

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_fork_type': _('Fork has to be the same type as parent')
        }

        def _validate_python(self, value, state):
            if old_data['repo_type'] != value:
                msg = self.message('invalid_fork_type', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(repo_type=msg)
                )
    return _validator


def CanWriteGroup(old_data=None):
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'permission_denied': _("You don't have permissions "
                                   "to create repository in this group"),
            'permission_denied_root': _("no permission to create repository "
                                        "in root location")
        }

        def _convert_to_python(self, value, state):
            # root location
            if value == -1:
                return None
            return value

        def _validate_python(self, value, state):
            gr = db.RepoGroup.get(value)
            gr_name = gr.group_name if gr is not None else None # None means ROOT location

            # create repositories with write permission on group is set to true
            group_admin = auth.HasRepoGroupPermissionLevel('admin')(gr_name,
                                            'can write into group validator')
            group_write = auth.HasRepoGroupPermissionLevel('write')(gr_name,
                                            'can write into group validator')
            forbidden = not (group_admin or group_write)
            can_create_repos = auth.HasPermissionAny('hg.admin', 'hg.create.repository')
            gid = (old_data['repo_group'].get('group_id')
                   if (old_data and 'repo_group' in old_data) else None)
            value_changed = gid != value
            new = not old_data
            # do check if we changed the value, there's a case that someone got
            # revoked write permissions to a repository, he still created, we
            # don't need to check permission if he didn't change the value of
            # groups in form box
            if value_changed or new:
                # parent group need to be existing
                if gr and forbidden:
                    msg = self.message('permission_denied', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(repo_type=msg)
                    )
                ## check if we can write to root location !
                elif gr is None and not can_create_repos():
                    msg = self.message('permission_denied_root', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(repo_type=msg)
                    )

    return _validator


def CanCreateGroup(can_create_in_root=False):
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'permission_denied': _("You don't have permissions "
                                   "to create a group in this location")
        }

        def to_python(self, value, state):
            # root location
            if value == -1:
                return None
            return value

        def _validate_python(self, value, state):
            gr = db.RepoGroup.get(value)
            gr_name = gr.group_name if gr is not None else None # None means ROOT location

            if can_create_in_root and gr is None:
                # we can create in root, we're fine no validations required
                return

            forbidden_in_root = gr is None and not can_create_in_root
            forbidden = not auth.HasRepoGroupPermissionLevel('admin')(gr_name, 'can create group validator')
            if forbidden_in_root or forbidden:
                msg = self.message('permission_denied', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(parent_group_id=msg)
                )

    return _validator


def ValidPerms(type_='repo'):
    if type_ == 'repo_group':
        EMPTY_PERM = 'group.none'
    elif type_ == 'repo':
        EMPTY_PERM = 'repository.none'
    elif type_ == 'user_group':
        EMPTY_PERM = 'usergroup.none'

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'perm_new_member_name':
                _('This username or user group name is not valid')
        }

        def to_python(self, value, state):
            perms_update = OrderedSet()
            perms_new = OrderedSet()
            # build a list of permission to update and new permission to create

            # CLEAN OUT ORG VALUE FROM NEW MEMBERS, and group them using
            new_perms_group = defaultdict(dict)
            for k, v in value.copy().items():
                if k.startswith('perm_new_member'):
                    del value[k]
                    _type, part = k.split('perm_new_member_')
                    args = part.split('_')
                    if len(args) == 1:
                        new_perms_group[args[0]]['perm'] = v
                    elif len(args) == 2:
                        _key, pos = args
                        new_perms_group[pos][_key] = v

            # fill new permissions in order of how they were added
            for k in sorted(new_perms_group, key=lambda k: int(k)):
                perm_dict = new_perms_group[k]
                new_member = perm_dict.get('name')
                new_perm = perm_dict.get('perm')
                new_type = perm_dict.get('type')
                if new_member and new_perm and new_type:
                    perms_new.add((new_member, new_perm, new_type))

            for k, v in value.items():
                if k.startswith('u_perm_') or k.startswith('g_perm_'):
                    member_name = k[7:]
                    t = {'u': 'user',
                         'g': 'users_group'
                    }[k[0]]
                    if member_name == db.User.DEFAULT_USER_NAME:
                        if asbool(value.get('repo_private')):
                            # set none for default when updating to
                            # private repo protects against form manipulation
                            v = EMPTY_PERM
                    perms_update.add((member_name, v, t))

            value['perms_updates'] = list(perms_update)
            value['perms_new'] = list(perms_new)

            # update permissions
            for k, v, t in perms_new:
                try:
                    if t == 'user':
                        _user_db = db.User.query() \
                            .filter(db.User.active == True) \
                            .filter(db.User.username == k).one()
                    if t == 'users_group':
                        _user_db = db.UserGroup.query() \
                            .filter(db.UserGroup.users_group_active == True) \
                            .filter(db.UserGroup.users_group_name == k).one()

                except Exception as e:
                    log.warning('Error validating %s permission %s', t, k)
                    msg = self.message('perm_new_member_type', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(perm_new_member_name=msg)
                    )
            return value
    return _validator


def ValidSettings():
    class _validator(formencode.validators.FancyValidator):
        def _convert_to_python(self, value, state):
            # settings  form for users that are not admin
            # can't edit certain parameters, it's extra backup if they mangle
            # with forms

            forbidden_params = [
                'user', 'repo_type',
                'repo_enable_downloads', 'repo_enable_statistics'
            ]

            for param in forbidden_params:
                if param in value:
                    del value[param]
            return value

        def _validate_python(self, value, state):
            pass
    return _validator


def ValidPath():
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'invalid_path': _('This is not a valid path')
        }

        def _validate_python(self, value, state):
            if not os.path.isdir(value):
                msg = self.message('invalid_path', state)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(paths_root_path=msg)
                )
    return _validator


def UniqSystemEmail(old_data=None):
    old_data = old_data or {}

    class _validator(formencode.validators.FancyValidator):
        messages = {
            'email_taken': _('This email address is already in use')
        }

        def _convert_to_python(self, value, state):
            return value.lower()

        def _validate_python(self, value, state):
            if (old_data.get('email') or '').lower() != value:
                user = db.User.get_by_email(value)
                if user is not None:
                    msg = self.message('email_taken', state)
                    raise formencode.Invalid(msg, value, state,
                        error_dict=dict(email=msg)
                    )
    return _validator


def ValidSystemEmail():
    class _validator(formencode.validators.FancyValidator):
        messages = {
            'non_existing_email': _('Email address "%(email)s" not found')
        }

        def _convert_to_python(self, value, state):
            return value.lower()

        def _validate_python(self, value, state):
            user = db.User.get_by_email(value)
            if user is None:
                msg = self.message('non_existing_email', state, email=value)
                raise formencode.Invalid(msg, value, state,
                    error_dict=dict(email=msg)
                )

    return _validator


def LdapLibValidator():
    class _validator(formencode.validators.FancyValidator):
        messages = {

        }

        def _validate_python(self, value, state):
            try:
                import ldap
                ldap  # pyflakes silence !
            except ImportError:
                raise LdapImportError()

    return _validator


def AttrLoginValidator():
    class _validator(formencode.validators.UnicodeString):
        messages = {
            'invalid_cn':
                  _('The LDAP Login attribute of the CN must be specified - '
                    'this is the name of the attribute that is equivalent '
                    'to "username"')
        }
        messages['empty'] = messages['invalid_cn']

    return _validator


def ValidIp():
    class _validator(CIDR):
        messages = dict(
            badFormat=_('Please enter a valid IPv4 or IPv6 address'),
            illegalBits=_('The network size (bits) must be within the range'
                ' of 0-32 (not %(bits)r)')
        )

        def to_python(self, value, state):
            v = super(_validator, self).to_python(value, state)
            v = v.strip()
            net = ipaddr.IPNetwork(address=v)
            if isinstance(net, ipaddr.IPv4Network):
                # if IPv4 doesn't end with a mask, add /32
                if '/' not in value:
                    v += '/32'
            if isinstance(net, ipaddr.IPv6Network):
                # if IPv6 doesn't end with a mask, add /128
                if '/' not in value:
                    v += '/128'
            return v

        def _validate_python(self, value, state):
            try:
                addr = value.strip()
                # this raises an ValueError if address is not IPv4 or IPv6
                ipaddr.IPNetwork(address=addr)
            except ValueError:
                raise formencode.Invalid(self.message('badFormat', state),
                                         value, state)

    return _validator


def FieldKey():
    class _validator(formencode.validators.FancyValidator):
        messages = dict(
            badFormat=_('Key name can only consist of letters, '
                        'underscore, dash or numbers')
        )

        def _validate_python(self, value, state):
            if not re.match('[a-zA-Z0-9_-]+$', value):
                raise formencode.Invalid(self.message('badFormat', state),
                                         value, state)
    return _validator


def BasePath():
    class _validator(formencode.validators.FancyValidator):
        messages = dict(
            badPath=_('Filename cannot be inside a directory')
        )

        def _convert_to_python(self, value, state):
            return value

        def _validate_python(self, value, state):
            if value != os.path.basename(value):
                raise formencode.Invalid(self.message('badPath', state),
                                         value, state)
    return _validator


def ValidAuthPlugins():
    class _validator(formencode.validators.FancyValidator):
        messages = dict(
            import_duplicate=_('Plugins %(loaded)s and %(next_to_load)s both export the same name')
        )

        def _convert_to_python(self, value, state):
            # filter empty values
            return [s for s in value if s not in [None, '']]

        def _validate_python(self, value, state):
            from kallithea.lib import auth_modules
            module_list = value
            unique_names = {}
            try:
                for module in module_list:
                    plugin = auth_modules.loadplugin(module)
                    plugin_name = plugin.name
                    if plugin_name in unique_names:
                        msg = self.message('import_duplicate', state,
                                loaded=unique_names[plugin_name],
                                next_to_load=plugin_name)
                        raise formencode.Invalid(msg, value, state)
                    unique_names[plugin_name] = plugin
            except (ImportError, AttributeError, TypeError) as e:
                raise formencode.Invalid(str(e), value, state)

    return _validator
