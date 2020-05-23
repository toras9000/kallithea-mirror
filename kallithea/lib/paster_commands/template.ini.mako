## -*- coding: utf-8 -*-
<%text>##</%text>#################################################################################
<%text>##</%text>#################################################################################
<%text>##</%text> Kallithea config file generated with kallithea-cli ${'%-27s' % version       }##
<%text>##</%text>                                                                               ##
<%text>##</%text> The %(here)s variable will generally be replaced with the parent directory of ##
<%text>##</%text> this file. Other use of % must be escaped as %% .                             ##
<%text>##</%text>#################################################################################
<%text>##</%text>#################################################################################

[DEFAULT]

<%text>##</%text>##############################################################################
<%text>##</%text> Email settings                                                             ##
<%text>##</%text>                                                                            ##
<%text>##</%text> Refer to the documentation ("Email settings") for more details.            ##
<%text>##</%text>                                                                            ##
<%text>##</%text> It is recommended to use a valid sender address that passes access         ##
<%text>##</%text> validation and spam filtering in mail servers.                             ##
<%text>##</%text>##############################################################################

<%text>##</%text> 'From' header for application emails. You can optionally add a name.
<%text>##</%text> Default:
#app_email_from = Kallithea
<%text>##</%text> Examples:
#app_email_from = Kallithea <kallithea-noreply@example.com>
#app_email_from = kallithea-noreply@example.com

<%text>##</%text> Subject prefix for application emails.
<%text>##</%text> A space between this prefix and the real subject is automatically added.
<%text>##</%text> Default:
#email_prefix =
<%text>##</%text> Example:
#email_prefix = [Kallithea]

<%text>##</%text> Recipients for error emails and fallback recipients of application mails.
<%text>##</%text> Multiple addresses can be specified, comma-separated.
<%text>##</%text> Only addresses are allowed, do not add any name part.
<%text>##</%text> Default:
#email_to =
<%text>##</%text> Examples:
#email_to = admin@example.com
#email_to = admin@example.com,another_admin@example.com
email_to =

<%text>##</%text> 'From' header for error emails. You can optionally add a name.
<%text>##</%text> Default: (none)
<%text>##</%text> Examples:
#error_email_from = Kallithea Errors <kallithea-noreply@example.com>
#error_email_from = kallithea_errors@example.com
error_email_from =

<%text>##</%text> SMTP server settings
<%text>##</%text> If specifying credentials, make sure to use secure connections.
<%text>##</%text> Default: Send unencrypted unauthenticated mails to the specified smtp_server.
<%text>##</%text> For "SSL", use smtp_use_ssl = true and smtp_port = 465.
<%text>##</%text> For "STARTTLS", use smtp_use_tls = true and smtp_port = 587.
smtp_server =
smtp_username =
smtp_password =
smtp_port =
smtp_use_ssl = false
smtp_use_tls = false

%if http_server != 'uwsgi':
<%text>##</%text> Entry point for 'gearbox serve'
[server:main]
host = ${host}
port = ${port}

%if http_server == 'gearbox':
<%text>##</%text> Gearbox default web server ##
use = egg:gearbox#wsgiref
<%text>##</%text> nr of worker threads to spawn
threadpool_workers = 1
<%text>##</%text> max request before thread respawn
threadpool_max_requests = 100
<%text>##</%text> option to use threads of process
use_threadpool = true

%elif http_server == 'gevent':
<%text>##</%text> Gearbox gevent web server ##
use = egg:gearbox#gevent

%elif http_server == 'waitress':
<%text>##</%text> WAITRESS ##
use = egg:waitress#main
<%text>##</%text> number of worker threads
threads = 1
<%text>##</%text> MAX BODY SIZE 100GB
max_request_body_size = 107374182400
<%text>##</%text> use poll instead of select, fixes fd limits, may not work on old
<%text>##</%text> windows systems.
#asyncore_use_poll = True

%elif http_server == 'gunicorn':
<%text>##</%text> GUNICORN ##
use = egg:gunicorn#main
<%text>##</%text> number of process workers. You must set `instance_id = *` when this option
<%text>##</%text> is set to more than one worker
workers = 4
<%text>##</%text> process name
proc_name = kallithea
<%text>##</%text> type of worker class, one of sync, eventlet, gevent, tornado
<%text>##</%text> recommended for bigger setup is using of of other than sync one
worker_class = sync
max_requests = 1000
<%text>##</%text> amount of time a worker can handle request before it gets killed and
<%text>##</%text> restarted
timeout = 3600

%endif
%else:
<%text>##</%text> UWSGI ##
[uwsgi]
<%text>##</%text> Note: this section is parsed by the uWSGI .ini parser when run as:
<%text>##</%text> uwsgi --venv /srv/kallithea/venv --ini-paste-logged my.ini
<%text>##</%text> Note: in uWSGI 2.0.18 or older, pastescript needs to be installed to
<%text>##</%text> get correct application logging. In later versions this is not necessary.
<%text>##</%text> pip install pastescript

<%text>##</%text> HTTP Basics:
http-socket = ${host}:${port}
buffer-size = 65535                    ; Mercurial will use huge GET headers for discovery

<%text>##</%text> Scaling:
master = true                          ; Use separate master and worker processes
auto-procname = true                   ; Name worker processes accordingly
lazy = true                            ; App *must* be loaded in workers - db connections can't be shared
workers = 4                            ; On demand scaling up to this many worker processes
cheaper = 1                            ; Initial and on demand scaling down to this many worker processes
max-requests = 1000                    ; Graceful reload of worker processes to avoid leaks

<%text>##</%text> Tweak defaults:
strict = true                          ; Fail on unknown config directives
enable-threads = true                  ; Enable Python threads (not threaded workers)
vacuum = true                          ; Delete sockets during shutdown
single-interpreter = true
die-on-term = true                     ; Shutdown when receiving SIGTERM (default is respawn)
need-app = true                        ; Exit early if no app can be loaded.
reload-on-exception = true             ; Don't assume that the application worker can process more requests after a severe error

%endif
<%text>##</%text> middleware for hosting the WSGI application under a URL prefix
#[filter:proxy-prefix]
#use = egg:PasteDeploy#prefix
#prefix = /<your-prefix>

[app:main]
use = egg:kallithea
<%text>##</%text> enable proxy prefix middleware
#filter-with = proxy-prefix

full_stack = true
static_files = true

<%text>##</%text> Internationalization (see setup documentation for details)
<%text>##</%text> By default, the languages requested by the browser are used if available, with English as default.
<%text>##</%text> Set i18n.enabled=false to disable automatic language choice.
#i18n.enabled = true
<%text>##</%text> To Force a language, set i18n.enabled=false and specify the language in i18n.lang.
<%text>##</%text> Valid values are the names of subdirectories in kallithea/i18n with a LC_MESSAGES/kallithea.mo
#i18n.lang = en

cache_dir = %(here)s/data
index_dir = %(here)s/data/index

<%text>##</%text> uncomment and set this path to use archive download cache
archive_cache_dir = %(here)s/tarballcache

<%text>##</%text> change this to unique ID for security
app_instance_uuid = ${uuid()}

<%text>##</%text> cut off limit for large diffs (size in bytes)
cut_off_limit = 256000

<%text>##</%text> force https in Kallithea, fixes https redirects, assumes it's always https
force_https = false

<%text>##</%text> use Strict-Transport-Security headers
use_htsts = false

<%text>##</%text> number of commits stats will parse on each iteration
commit_parse_limit = 25

<%text>##</%text> Path to Python executable to be used for git hooks.
<%text>##</%text> This value will be written inside the git hook scripts as the text
<%text>##</%text> after '#!' (shebang). When empty or not defined, the value of
<%text>##</%text> 'sys.executable' at the time of installation of the git hooks is
<%text>##</%text> used, which is correct in many cases but for example not when using uwsgi.
<%text>##</%text> If you change this setting, you should reinstall the Git hooks via
<%text>##</%text> Admin > Settings > Remap and Rescan.
#git_hook_interpreter = /srv/kallithea/venv/bin/python3
%if git_hook_interpreter:
git_hook_interpreter = ${git_hook_interpreter}
%endif

<%text>##</%text> path to git executable
git_path = git

<%text>##</%text> git rev filter option, --all is the default filter, if you need to
<%text>##</%text> hide all refs in changelog switch this to --branches --tags
#git_rev_filter = --branches --tags

<%text>##</%text> RSS feed options
rss_cut_off_limit = 256000
rss_items_per_page = 10
rss_include_diff = false

<%text>##</%text> options for showing and identifying changesets
show_sha_length = 12
show_revision_number = false

<%text>##</%text> Canonical URL to use when creating full URLs in UI and texts.
<%text>##</%text> Useful when the site is available under different names or protocols.
<%text>##</%text> Defaults to what is provided in the WSGI environment.
#canonical_url = https://kallithea.example.com/repos

<%text>##</%text> gist URL alias, used to create nicer urls for gist. This should be an
<%text>##</%text> url that does rewrites to _admin/gists/<gistid>.
<%text>##</%text> example: http://gist.example.com/{gistid}. Empty means use the internal
<%text>##</%text> Kallithea url, ie. http[s]://kallithea.example.com/_admin/gists/<gistid>
gist_alias_url =

<%text>##</%text> default encoding used to convert from and to unicode
<%text>##</%text> can be also a comma separated list of encoding in case of mixed encodings
default_encoding = utf-8

<%text>##</%text> Set Mercurial encoding, similar to setting HGENCODING before launching Kallithea
hgencoding = utf-8

<%text>##</%text> issue tracker for Kallithea (leave blank to disable, absent for default)
#bugtracker = https://bitbucket.org/conservancy/kallithea/issues

<%text>##</%text> issue tracking mapping for commit messages, comments, PR descriptions, ...
<%text>##</%text> Refer to the documentation ("Integration with issue trackers") for more details.

<%text>##</%text> regular expression to match issue references
<%text>##</%text> This pattern may/should contain parenthesized groups, that can
<%text>##</%text> be referred to in issue_server_link or issue_sub using Python backreferences
<%text>##</%text> (e.g. \1, \2, ...). You can also create named groups with '(?P<groupname>)'.
<%text>##</%text> To require mandatory whitespace before the issue pattern, use:
<%text>##</%text> (?:^|(?<=\s)) before the actual pattern, and for mandatory whitespace
<%text>##</%text> behind the issue pattern, use (?:$|(?=\s)) after the actual pattern.

issue_pat = #(\d+)

<%text>##</%text> server url to the issue
<%text>##</%text> This pattern may/should contain backreferences to parenthesized groups in issue_pat.
<%text>##</%text> A backreference can be \1, \2, ... or \g<groupname> if you specified a named group
<%text>##</%text> called 'groupname' in issue_pat.
<%text>##</%text> The special token {repo} is replaced with the full repository name
<%text>##</%text> including repository groups, while {repo_name} is replaced with just
<%text>##</%text> the name of the repository.

issue_server_link = https://issues.example.com/{repo}/issue/\1

<%text>##</%text> substitution pattern to use as the link text
<%text>##</%text> If issue_sub is empty, the text matched by issue_pat is retained verbatim
<%text>##</%text> for the link text. Otherwise, the link text is that of issue_sub, with any
<%text>##</%text> backreferences to groups in issue_pat replaced.

issue_sub =

<%text>##</%text> issue_pat, issue_server_link and issue_sub can have suffixes to specify
<%text>##</%text> multiple patterns, to other issues server, wiki or others
<%text>##</%text> below an example how to create a wiki pattern
<%text>##</%text> wiki-some-id -> https://wiki.example.com/some-id

#issue_pat_wiki = wiki-(\S+)
#issue_server_link_wiki = https://wiki.example.com/\1
#issue_sub_wiki = WIKI-\1

<%text>##</%text> alternative return HTTP header for failed authentication. Default HTTP
<%text>##</%text> response is 401 HTTPUnauthorized. Currently Mercurial clients have trouble with
<%text>##</%text> handling that. Set this variable to 403 to return HTTPForbidden
auth_ret_code =

<%text>##</%text> allows to change the repository location in settings page
allow_repo_location_change = True

<%text>##</%text> allows to setup custom hooks in settings page
allow_custom_hooks_settings = True

<%text>##</%text> extra extensions for indexing, space separated and without the leading '.'.
#index.extensions =
#    gemfile
#    lock

<%text>##</%text> extra filenames for indexing, space separated
#index.filenames =
#    .dockerignore
#    .editorconfig
#    INSTALL
#    CHANGELOG

<%text>##</%text>##################################
<%text>##</%text>            SSH CONFIG          ##
<%text>##</%text>##################################

<%text>##</%text> SSH is disabled by default, until an Administrator decides to enable it.
ssh_enabled = false

<%text>##</%text> File where users' SSH keys will be stored *if* ssh_enabled is true.
#ssh_authorized_keys = /home/kallithea/.ssh/authorized_keys
%if user_home_path:
ssh_authorized_keys = ${user_home_path}/.ssh/authorized_keys
%endif

<%text>##</%text> Path to be used in ssh_authorized_keys file to invoke kallithea-cli with ssh-serve.
#kallithea_cli_path = /srv/kallithea/venv/bin/kallithea-cli
%if kallithea_cli_path:
kallithea_cli_path = ${kallithea_cli_path}
%endif

<%text>##</%text> Locale to be used in the ssh-serve command.
<%text>##</%text> This is needed because an SSH client may try to use its own locale
<%text>##</%text> settings, which may not be available on the server.
<%text>##</%text> See `locale -a` for valid values on this system.
#ssh_locale = C.UTF-8
%if ssh_locale:
ssh_locale = ${ssh_locale}
%endif

<%text>##</%text>##################################
<%text>##</%text>         CELERY CONFIG          ##
<%text>##</%text>##################################

<%text>##</%text> Note: Celery doesn't support Windows.
use_celery = false

<%text>##</%text> Celery config settings from https://docs.celeryproject.org/en/4.4.0/userguide/configuration.html prefixed with 'celery.'.

<%text>##</%text> Example: use the message queue on the local virtual host 'kallitheavhost' as the RabbitMQ user 'kallithea':
celery.broker_url = amqp://kallithea:thepassword@localhost:5672/kallitheavhost

celery.result.backend = db+sqlite:///celery-results.db

#celery.amqp.task.result.expires = 18000

celery.worker_concurrency = 2
celery.worker_max_tasks_per_child = 1

<%text>##</%text> If true, tasks will never be sent to the queue, but executed locally instead.
celery.task_always_eager = false

<%text>##</%text>##################################
<%text>##</%text>          BEAKER CACHE          ##
<%text>##</%text>##################################

beaker.cache.data_dir = %(here)s/data/cache/data
beaker.cache.lock_dir = %(here)s/data/cache/lock

beaker.cache.regions = long_term,long_term_file

beaker.cache.long_term.type = memory
beaker.cache.long_term.expire = 36000
beaker.cache.long_term.key_length = 256

beaker.cache.long_term_file.type = file
beaker.cache.long_term_file.expire = 604800
beaker.cache.long_term_file.key_length = 256

<%text>##</%text>##################################
<%text>##</%text>        BEAKER SESSION          ##
<%text>##</%text>##################################

<%text>##</%text> Name of session cookie. Should be unique for a given host and path, even when running
<%text>##</%text> on different ports. Otherwise, cookie sessions will be shared and messed up.
session.key = kallithea
<%text>##</%text> Sessions should always only be accessible by the browser, not directly by JavaScript.
session.httponly = true
<%text>##</%text> Session lifetime. 2592000 seconds is 30 days.
session.timeout = 2592000

<%text>##</%text> Server secret used with HMAC to ensure integrity of cookies.
session.secret = ${uuid()}
<%text>##</%text> Further, encrypt the data with AES.
#session.encrypt_key = <key_for_encryption>
#session.validate_key = <validation_key>

<%text>##</%text> Type of storage used for the session, current types are
<%text>##</%text> dbm, file, memcached, database, and memory.

<%text>##</%text> File system storage of session data. (default)
#session.type = file

<%text>##</%text> Cookie only, store all session data inside the cookie. Requires secure secrets.
#session.type = cookie

<%text>##</%text> Database storage of session data.
#session.type = ext:database
#session.sa.url = postgresql://postgres:qwe@localhost/kallithea
#session.table_name = db_session

<%text>##</%text>##################################
<%text>##</%text>        ERROR HANDLING          ##
<%text>##</%text>##################################

<%text>##</%text> Show a nice error page for application HTTP errors and exceptions (default true)
#errorpage.enabled = true

<%text>##</%text> Enable Backlash client-side interactive debugger (default false)
<%text>##</%text> WARNING: *THIS MUST BE false IN PRODUCTION ENVIRONMENTS!!!*
<%text>##</%text> This debug mode will allow all visitors to execute malicious code.
#debug = false

<%text>##</%text> Enable Backlash server-side error reporting (unless debug mode handles it client-side) (default true)
#trace_errors.enable = true
<%text>##</%text> Errors will be reported by mail if trace_errors.error_email is set.

<%text>##</%text> Propagate email settings to ErrorReporter of TurboGears2
<%text>##</%text> You do not normally need to change these lines
get trace_errors.smtp_server = smtp_server
get trace_errors.smtp_port = smtp_port
get trace_errors.from_address = error_email_from
get trace_errors.error_email = email_to
get trace_errors.smtp_username = smtp_username
get trace_errors.smtp_password = smtp_password
get trace_errors.smtp_use_tls = smtp_use_tls

%if error_aggregation_service == 'sentry':
<%text>##</%text>##############
<%text>##</%text>  [sentry]  ##
<%text>##</%text>##############

<%text>##</%text> sentry is a alternative open source error aggregator
<%text>##</%text> you must install python packages `sentry` and `raven` to enable

sentry.dsn = YOUR_DNS
sentry.servers =
sentry.name =
sentry.key =
sentry.public_key =
sentry.secret_key =
sentry.project =
sentry.site =
sentry.include_paths =
sentry.exclude_paths =

%endif

<%text>##</%text>################################
<%text>##</%text>        LOGVIEW CONFIG        ##
<%text>##</%text>################################

logview.sqlalchemy = #faa
logview.pylons.templating = #bfb
logview.pylons.util = #eee

<%text>##</%text>#######################
<%text>##</%text>      DB CONFIG      ##
<%text>##</%text>#######################

%if database_engine == 'sqlite':
<%text>##</%text> SQLITE [default]
sqlalchemy.url = sqlite:///%(here)s/kallithea.db?timeout=60

%elif database_engine == 'postgres':
<%text>##</%text> POSTGRESQL
sqlalchemy.url = postgresql://user:pass@localhost/kallithea

%elif database_engine == 'mysql':
<%text>##</%text> MySQL
sqlalchemy.url = mysql://user:pass@localhost/kallithea?charset=utf8

%endif
<%text>##</%text> see sqlalchemy docs for other backends

sqlalchemy.pool_recycle = 3600

<%text>##</%text>##############################
<%text>##</%text>   ALEMBIC CONFIGURATION    ##
<%text>##</%text>##############################

[alembic]
script_location = kallithea:alembic

<%text>##</%text>##############################
<%text>##</%text>   LOGGING CONFIGURATION    ##
<%text>##</%text>##############################

[loggers]
keys = root, routes, kallithea, sqlalchemy, tg, gearbox, beaker, templates, whoosh_indexer, werkzeug, backlash

[handlers]
keys = console, console_color, console_color_sql, null

[formatters]
keys = generic, color_formatter, color_formatter_sql

<%text>##</%text>###########
<%text>##</%text> LOGGERS ##
<%text>##</%text>###########

[logger_root]
level = NOTSET
handlers = console
<%text>##</%text> For coloring based on log level:
#handlers = console_color

[logger_routes]
level = WARN
handlers =
qualname = routes.middleware
<%text>##</%text> "level = DEBUG" logs the route matched and routing variables.

[logger_beaker]
level = WARN
handlers =
qualname = beaker.container

[logger_templates]
level = WARN
handlers =
qualname = pylons.templating

[logger_kallithea]
level = WARN
handlers =
qualname = kallithea

[logger_tg]
level = WARN
handlers =
qualname = tg

[logger_gearbox]
level = WARN
handlers =
qualname = gearbox

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine
<%text>##</%text> For coloring based on log level and pretty printing of SQL:
#level = INFO
#handlers = console_color_sql
#propagate = 0

[logger_whoosh_indexer]
level = WARN
handlers =
qualname = whoosh_indexer

[logger_werkzeug]
level = WARN
handlers =
qualname = werkzeug

[logger_backlash]
level = WARN
handlers =
qualname = backlash

<%text>##</%text>############
<%text>##</%text> HANDLERS ##
<%text>##</%text>############

[handler_console]
class = StreamHandler
args = (sys.stderr,)
formatter = generic

[handler_console_color]
<%text>##</%text> ANSI color coding based on log level
class = StreamHandler
args = (sys.stderr,)
formatter = color_formatter

[handler_console_color_sql]
<%text>##</%text> ANSI color coding and pretty printing of SQL statements
class = StreamHandler
args = (sys.stderr,)
formatter = color_formatter_sql

[handler_null]
class = NullHandler
args = ()

<%text>##</%text>##############
<%text>##</%text> FORMATTERS ##
<%text>##</%text>##############

[formatter_generic]
format = %(asctime)s.%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %Y-%m-%d %H:%M:%S

[formatter_color_formatter]
class = kallithea.lib.colored_formatter.ColorFormatter
format = %(asctime)s.%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %Y-%m-%d %H:%M:%S

[formatter_color_formatter_sql]
class = kallithea.lib.colored_formatter.ColorFormatterSql
format = %(asctime)s.%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %Y-%m-%d %H:%M:%S

<%text>##</%text>###############
<%text>##</%text> SSH LOGGING ##
<%text>##</%text>###############

<%text>##</%text> The default loggers use 'handler_console' that uses StreamHandler with
<%text>##</%text> destination 'sys.stderr'. In the context of the SSH server process, these log
<%text>##</%text> messages would be sent to the client, which is normally not what you want.
<%text>##</%text> By default, when running ssh-serve, just use NullHandler and disable logging
<%text>##</%text> completely. For other logging options, see:
<%text>##</%text> https://docs.python.org/2/library/logging.handlers.html

[ssh_serve:logger_root]
level = CRITICAL
handlers = null

<%text>##</%text> Note: If logging is configured with other handlers, they might need similar
<%text>##</%text> muting for ssh-serve too.
