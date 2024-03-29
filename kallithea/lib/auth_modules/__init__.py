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
Authentication modules
"""

import importlib
import logging
import traceback
from inspect import isfunction

from kallithea.lib.auth import AuthUser
from kallithea.lib.compat import hybrid_property
from kallithea.lib.utils2 import PasswordGenerator, asbool
from kallithea.model import db, meta, validators
from kallithea.model.user import UserModel
from kallithea.model.user_group import UserGroupModel


log = logging.getLogger(__name__)


class LazyFormencode(object):
    def __init__(self, formencode_obj, *args, **kwargs):
        self.formencode_obj = formencode_obj
        self.args = args
        self.kwargs = kwargs

    def __call__(self, *args, **kwargs):
        formencode_obj = self.formencode_obj
        if isfunction(formencode_obj):
            # case we wrap validators into functions
            formencode_obj = self.formencode_obj(*args, **kwargs)
        return formencode_obj(*self.args, **self.kwargs)


class KallitheaAuthPluginBase(object):
    auth_func_attrs = {
        "username": "unique username",
        "firstname": "first name",
        "lastname": "last name",
        "email": "email address",
        "groups": '["list", "of", "groups"]',
        "extern_name": "name in external source of record",
        "admin": 'True|False defines if user should be Kallithea admin',
    }

    @property
    def validators(self):
        """
        Exposes Kallithea validators modules
        """
        # this is a hack to overcome issues with pylons threadlocals and
        # translator object _() not being registered properly.
        class LazyCaller(object):
            def __init__(self, name):
                self.validator_name = name

            def __call__(self, *args, **kwargs):
                obj = getattr(validators, self.validator_name)
                #log.debug('Initializing lazy formencode object: %s', obj)
                return LazyFormencode(obj, *args, **kwargs)

        class ProxyGet(object):
            def __getattribute__(self, name):
                return LazyCaller(name)

        return ProxyGet()

    @hybrid_property
    def name(self):
        """
        Returns the name of this authentication plugin.

        :returns: string
        """
        raise NotImplementedError("Not implemented in base class")

    @hybrid_property
    def is_container_auth(self):
        """
        Returns bool if this module uses container auth.

        This property will trigger an automatic call to authenticate on
        a visit to the website or during a push/pull.

        :returns: bool
        """
        return False

    def accepts(self, user, accepts_empty=True):
        """
        Checks if this authentication module should accept a request for
        the current user.

        :param user: user object fetched using plugin's get_user() method.
        :param accepts_empty: if True accepts don't allow the user to be empty
        :returns: boolean
        """
        plugin_name = self.name
        if not user and not accepts_empty:
            log.debug('User is empty not allowed to authenticate')
            return False

        if user and user.extern_type and user.extern_type != plugin_name:
            log.debug('User %s should authenticate using %s this is %s, skipping',
                      user, user.extern_type, plugin_name)

            return False
        return True

    def get_user(self, username=None, **kwargs):
        """
        Helper method for user fetching in plugins, by default it's using
        simple fetch by username, but this method can be customized in plugins
        eg. container auth plugin to fetch user by environ params

        :param username: username if given to fetch from database
        :param kwargs: extra arguments needed for user fetching.
        """
        user = None
        log.debug('Trying to fetch user `%s` from Kallithea database',
                  username)
        if username:
            user = db.User.get_by_username_or_email(username)
        else:
            log.debug('provided username:`%s` is empty skipping...', username)
        return user

    def settings(self):
        """
        Return a list of the form:
        [
            {
                "name": "OPTION_NAME",
                "type": "[bool|password|string|int|select]",
                ["values": ["opt1", "opt2", ...]]
                "validator": "expr"
                "description": "A short description of the option" [,
                "default": Default Value],
                ["formname": "Friendly Name for Forms"]
            } [, ...]
        ]

        This is used to interrogate the authentication plugin as to what
        settings it expects to be present and configured.

        'type' is a shorthand notation for what kind of value this option is.
        This is primarily used by the auth web form to control how the option
        is configured.
                bool : checkbox
                password : password input box
                string : input box
                select : single select dropdown

        'validator' is an lazy instantiated form field validator object, ala
        formencode. You need to *call* this object to init the validators.
        All calls to Kallithea validators should be used through self.validators
        which is a lazy loading proxy of formencode module.
        """
        raise NotImplementedError("Not implemented in base class")

    def plugin_settings(self):
        """
        This method is called by the authentication framework, not the .settings()
        method. This method adds a few default settings (e.g., "enabled"), so that
        plugin authors don't have to maintain a bunch of boilerplate.

        OVERRIDING THIS METHOD WILL CAUSE YOUR PLUGIN TO FAIL.
        """

        settings = self.settings()
        settings.insert(0, {
            "name": "enabled",
            "validator": self.validators.StringBoolean(if_missing=False),
            "type": "bool",
            "description": "Enable or Disable this Authentication Plugin",
            "formname": "Enabled"
            }
        )
        return settings

    def auth(self, userobj, username, passwd, settings, **kwargs):
        """
        Given a user object (which may be None), username, a plaintext password,
        and a settings object (containing all the keys needed as listed in settings()),
        authenticate this user's login attempt.

        Return None on failure. On success, return a dictionary with keys from
        KallitheaAuthPluginBase.auth_func_attrs.

        This is later validated for correctness.
        """
        raise NotImplementedError("not implemented in base class")

    def _authenticate(self, userobj, username, passwd, settings, **kwargs):
        """
        Wrapper to call self.auth() that validates call on it
        """
        user_data = self.auth(userobj, username, passwd, settings, **kwargs)
        if user_data is not None:
            return self._validate_auth_return(user_data)
        return None

    def _validate_auth_return(self, user_data):
        if not isinstance(user_data, dict):
            raise Exception('returned value from auth must be a dict')
        for k in self.auth_func_attrs:
            if k not in user_data:
                raise Exception('Missing %s attribute from returned data' % k)
        return user_data


class KallitheaExternalAuthPlugin(KallitheaAuthPluginBase):
    def use_fake_password(self):
        """
        Return a boolean that indicates whether or not we should set the user's
        password to a random value when it is authenticated by this plugin.
        If your plugin provides authentication, then you will generally want this.

        :returns: boolean
        """
        raise NotImplementedError("Not implemented in base class")

    def _authenticate(self, userobj, username, passwd, settings, **kwargs):
        user_data = super(KallitheaExternalAuthPlugin, self)._authenticate(
            userobj, username, passwd, settings, **kwargs)
        if user_data is not None:
            if userobj is None: # external authentication of unknown user that will be created soon
                def_user_perms = AuthUser(dbuser=db.User.get_default_user()).global_permissions
                active = 'hg.extern_activate.auto' in def_user_perms
            else:
                active = userobj.active

            if self.use_fake_password():
                # Randomize the PW because we don't need it, but don't want
                # them blank either
                passwd = PasswordGenerator().gen_password(length=8)

            log.debug('Updating or creating user info from %s plugin',
                      self.name)
            user = UserModel().create_or_update(
                username=user_data['username'],
                password=passwd,
                email=user_data["email"],
                firstname=user_data["firstname"],
                lastname=user_data["lastname"],
                active=active,
                admin=user_data["admin"],
                extern_name=user_data["extern_name"],
                extern_type=self.name,
            )
            # enforce user is just in given groups, all of them has to be ones
            # created from plugins. We store this info in _group_data JSON field
            groups = user_data['groups'] or []
            UserGroupModel().enforce_groups(user, groups, self.name)
            meta.Session().commit()
        return user_data


def loadplugin(plugin):
    """
    Imports, instantiates, and returns the authentication plugin in the module named by plugin
    (e.g., plugin='kallithea.lib.auth_modules.auth_internal'). Returns an instance of the
    KallitheaAuthPluginBase subclass on success, raises exceptions on failure.

    raises:
        AttributeError -- no KallitheaAuthPlugin class in the module
        TypeError -- if the KallitheaAuthPlugin is not a subclass of ours KallitheaAuthPluginBase
        ImportError -- if we couldn't import the plugin at all
    """
    log.debug("Importing %s", plugin)
    if not plugin.startswith('kallithea.lib.auth_modules.auth_'):
        parts = plugin.split('.lib.auth_modules.auth_', 1)
        if len(parts) == 2:
            _module, pn = parts
            plugin = 'kallithea.lib.auth_modules.auth_' + pn
    PLUGIN_CLASS_NAME = "KallitheaAuthPlugin"
    try:
        module = importlib.import_module(plugin)
    except (ImportError, TypeError):
        log.error(traceback.format_exc())
        # TODO: make this more error prone, if by some accident we screw up
        # the plugin name, the crash is pretty bad and hard to recover
        raise

    log.debug("Loaded auth plugin from %s (module:%s, file:%s)",
              plugin, module.__name__, module.__file__)

    pluginclass = getattr(module, PLUGIN_CLASS_NAME)
    if not issubclass(pluginclass, KallitheaAuthPluginBase):
        raise TypeError("Authentication class %s.KallitheaAuthPlugin is not "
                        "a subclass of %s" % (plugin, KallitheaAuthPluginBase))

    plugin = pluginclass()
    if plugin.plugin_settings.__func__ != KallitheaAuthPluginBase.plugin_settings:
        raise TypeError("Authentication class %s.KallitheaAuthPluginBase "
                        "has overridden the plugin_settings method, which is "
                        "forbidden." % plugin)
    return plugin


def get_auth_plugins():
    """Return a list of instances of plugins that are available and enabled"""
    auth_plugins = []
    for plugin_name in db.Setting.get_by_name("auth_plugins").app_settings_value:
        try:
            plugin = loadplugin(plugin_name)
        except Exception:
            log.exception('Failed to load authentication module %s' % (plugin_name))
        else:
            auth_plugins.append(plugin)
    return auth_plugins


def authenticate(username, password, environ=None):
    """
    Authentication function used for access control,
    It tries to authenticate based on enabled authentication modules.

    :param username: username can be empty for container auth
    :param password: password can be empty for container auth
    :param environ: environ headers passed for container auth
    :returns: None if auth failed, user_data dict if auth is correct
    """

    auth_plugins = get_auth_plugins()
    for plugin in auth_plugins:
        module = plugin.__class__.__module__
        log.debug('Trying authentication using %s', module)
        # load plugin settings from Kallithea database
        plugin_name = plugin.name
        plugin_settings = {}
        for v in plugin.plugin_settings():
            conf_key = "auth_%s_%s" % (plugin_name, v["name"])
            setting = db.Setting.get_by_name(conf_key)
            plugin_settings[v["name"]] = setting.app_settings_value if setting else None
        log.debug('Settings for auth plugin %s: %s', plugin_name, plugin_settings)

        if not asbool(plugin_settings["enabled"]):
            log.info("Authentication plugin %s is disabled, skipping for %s",
                     module, username)
            continue

        # use plugin's method of user extraction.
        user = plugin.get_user(username, environ=environ,
                               settings=plugin_settings)
        log.debug('Plugin %s extracted user `%s`', module, user)

        if user is not None and not user.active: # give up, way before creating AuthUser
            log.error("Rejecting authentication of in-active user %s", user)
            continue

        if not plugin.accepts(user):
            log.debug('Plugin %s does not accept user `%s` for authentication',
                      module, user)
            continue
        else:
            log.debug('Plugin %s accepted user `%s` for authentication',
                      module, user)
            # The user might have tried to authenticate using their email address,
            # then the username variable wouldn't contain a valid username.
            # But as the plugin has accepted the user, .username field should
            # have a valid username, so use it for authentication purposes.
            if user is not None:
                username = user.username

        log.info('Authenticating user using %s plugin', module)

        # _authenticate is a wrapper for .auth() method of plugin.
        # it checks if .auth() sends proper data. For KallitheaExternalAuthPlugin
        # it also maps users to Database and maps the attributes returned
        # from .auth() to Kallithea database. If this function returns data
        # then auth is correct.
        user_data = plugin._authenticate(user, username, password,
                                           plugin_settings,
                                           environ=environ or {})
        log.debug('Plugin user data: %s', user_data)

        if user_data is not None:
            log.debug('Plugin returned proper authentication data')
            return user_data

        # we failed to Auth because .auth() method didn't return the user
        if username:
            log.warning("User `%s` failed to authenticate against %s",
                        username, module)
    return None


def get_managed_fields(user):
    """return list of fields that are managed by the user's auth source, usually some of
    'username', 'firstname', 'lastname', 'email', 'password'
    """
    auth_plugins = get_auth_plugins()
    for plugin in auth_plugins:
        module = plugin.__class__.__module__
        log.debug('testing %s (%s) with auth plugin %s', user, user.extern_type, module)
        if plugin.name == user.extern_type:
            return plugin.get_managed_fields()
    log.error('no auth plugin %s found for %s', user.extern_type, user)
    return [] # TODO: Fail badly instead of allowing everything to be edited?
