.. _setup:

=====
Setup
=====


Setting up a Kallithea instance
-------------------------------

Some further details to the steps mentioned in the overview.

Create low level configuration file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First, you will need to create a Kallithea configuration file. The
configuration file is a ``.ini`` file that contains various low level settings
for Kallithea, e.g. configuration of how to use database, web server, email,
and logging.

Change to the desired directory (such as ``/srv/kallithea``) as the right user
and run the following command to create the file ``my.ini`` in the current
directory::

    kallithea-cli config-create my.ini http_server=waitress

To get a good starting point for your configuration, specify the http server
you intend to use. It can be ``waitress``, ``gearbox``, ``gevent``,
``gunicorn``, or ``uwsgi``. (Apache ``mod_wsgi`` will not use this
configuration file, and it is fine to keep the default http_server configuration
unused. ``mod_wsgi`` is configured using ``httpd.conf`` directives and a WSGI
wrapper script.)

Extra custom settings can be specified like::

    kallithea-cli config-create my.ini host=8.8.8.8 "[handler_console]" formatter=color_formatter

Populate the database
^^^^^^^^^^^^^^^^^^^^^

Next, you need to create the databases used by Kallithea. Kallithea currently
supports PostgreSQL, SQLite and MariaDB/MySQL databases. It is recommended to
start out using SQLite (the default) and move to PostgreSQL if it becomes a
bottleneck or to get a "proper" database. MariaDB/MySQL is also supported.

For PostgreSQL, run ``pip install psycopg2`` to get the database driver. Make
sure the PostgreSQL server is initialized and running. Make sure you have a
database user with password authentication with permissions to create databases
- for example by running::

    sudo -u postgres createuser 'kallithea' --pwprompt --createdb

For MariaDB/MySQL, run ``pip install mysqlclient`` to get the ``MySQLdb``
database driver. Make sure the database server is initialized and running. Make
sure you have a database user with password authentication with permissions to
create the database - for example by running::

    echo 'CREATE USER "kallithea"@"localhost" IDENTIFIED BY "password"' | sudo -u mysql mysql
    echo 'GRANT ALL PRIVILEGES ON `kallithea`.* TO "kallithea"@"localhost"' | sudo -u mysql mysql

Check and adjust ``sqlalchemy.url`` in your ``my.ini`` configuration file to use
this database.

Create the database, tables, and initial content by running the following
command::

    kallithea-cli db-create -c my.ini

This will first prompt you for a "root" path. This "root" path is the location
where Kallithea will store all of its repositories on the current machine. This
location must be writable for the running Kallithea application. Next,
``db-create`` will prompt you for a username and password for the initial admin
account it sets up for you.

The ``db-create`` values can also be given on the command line.
Example::

    kallithea-cli db-create -c my.ini --user=nn --password=secret --email=nn@example.com --repos=/srv/repos

The ``db-create`` command will create all needed tables and an
admin account. When choosing a root path you can either use a new
empty location, or a location which already contains existing
repositories. If you choose a location which contains existing
repositories Kallithea will add all of the repositories at the chosen
location to its database.  (Note: make sure you specify the correct
path to the root).

.. note:: It is also possible to use an existing database. For example,
          when using PostgreSQL without granting general createdb privileges to
          the PostgreSQL kallithea user, set ``sqlalchemy.url =
          postgresql://kallithea:password@localhost/kallithea`` and create the
          database like::

              sudo -u postgres createdb 'kallithea' --owner 'kallithea'
              kallithea-cli db-create -c my.ini --reuse

Running
^^^^^^^

You are now ready to use Kallithea. To run it using a gearbox web server,
simply execute::

    gearbox serve -c my.ini

- This command runs the Kallithea server. The web app should be available at
  http://127.0.0.1:5000. The IP address and port is configurable via the
  configuration file created in the previous step.
- Log in to Kallithea using the admin account created when running ``db-create``.
- The default permissions on each repository is read, and the owner is admin.
  Remember to update these if needed.
- In the admin panel you can toggle LDAP, anonymous, and permissions
  settings, as well as edit more advanced options on users and
  repositories.


Internationalization (i18n support)
-----------------------------------

The Kallithea web interface is automatically displayed in the user's preferred
language, as indicated by the browser. Thus, different users may see the
application in different languages. If the requested language is not available
(because the translation file for that language does not yet exist or is
incomplete), English is used.

If you want to disable automatic language detection and instead configure a
fixed language regardless of user preference, set ``i18n.enabled = false`` and
specify another language by setting ``i18n.lang`` in the Kallithea
configuration file.


Using Kallithea with SSH
------------------------

Kallithea supports repository access via SSH key based authentication.
This means:

- repository URLs like ``ssh://kallithea@example.com/name/of/repository``

- all network traffic for both read and write happens over the SSH protocol on
  port 22, without using HTTP/HTTPS nor the Kallithea WSGI application

- encryption and authentication protocols are managed by the system's ``sshd``
  process, with all users using the same Kallithea system user (e.g.
  ``kallithea``) when connecting to the SSH server, but with users' public keys
  in the Kallithea system user's `.ssh/authorized_keys` file granting each user
  sandboxed access to the repositories.

- users and admins can manage SSH public keys in the web UI

- in their SSH client configuration, users can configure how the client should
  control access to their SSH key - without passphrase, with passphrase, and
  optionally with passphrase caching in the local shell session (``ssh-agent``).
  This is standard SSH functionality, not something Kallithea provides or
  interferes with.

- network communication between client and server happens in a bidirectional
  stateful stream, and will in some cases be faster than HTTP/HTTPS with several
  stateless round-trips.

.. note:: At this moment, repository access via SSH has been tested on Unix
    only. Windows users that care about SSH are invited to test it and report
    problems, ideally contributing patches that solve these problems.

Users and admins can upload SSH public keys (e.g. ``.ssh/id_rsa.pub``) through
the web interface. The server's ``.ssh/authorized_keys`` file is automatically
maintained with an entry for each SSH key. Each entry will tell ``sshd`` to run
``kallithea-cli`` with the ``ssh-serve`` sub-command and the right Kallithea user ID
when encountering the corresponding SSH key.

To enable SSH repository access, Kallithea must be configured with the path to
the ``.ssh/authorized_keys`` file for the Kallithea user, and the path to the
``kallithea-cli`` command. Put something like this in the ``.ini`` file::

    ssh_enabled = true
    ssh_authorized_keys = /home/kallithea/.ssh/authorized_keys
    kallithea_cli_path = /srv/kallithea/venv/bin/kallithea-cli

The SSH service must be running, and the Kallithea user account must be active
(not necessarily with password access, but public key access must be enabled),
all file permissions must be set as sshd wants it, and ``authorized_keys`` must
be writeable by the Kallithea user.

.. note:: The ``authorized_keys`` file will be rewritten from scratch on
    each update. If it already exists with other data, Kallithea will not
    overwrite the existing ``authorized_keys``, and the server process will
    instead throw an exception. The system administrator thus cannot ssh
    directly to the Kallithea user but must use su/sudo from another account.

    If ``/home/kallithea/.ssh/`` (the directory of the path specified in the
    ``ssh_authorized_keys`` setting of the ``.ini`` file) does not exist as a
    directory, Kallithea will attempt to create it. If that path exists but is
    *not* a directory, or is not readable-writable-executable by the server
    process, the server process will raise an exception each time it attempts to
    write the ``authorized_keys`` file.

.. note:: It is possible to configure the SSH server to look for authorized
   keys in multiple files, for example reserving ``ssh/authorized_keys`` to be
   used for normal SSH and with Kallithea using
   ``.ssh/authorized_keys_kallithea``. In ``/etc/ssh/sshd_config`` set
   ``AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys_kallithea``
   and restart sshd, and in ``my.ini`` set ``ssh_authorized_keys =
   /home/kallithea/.ssh/authorized_keys_kallithea``. Note that this new
   location will apply to all system users, and that multiple entries for the
   same SSH key will shadow each other.

.. warning:: The handling of SSH access is steered directly by the command
    specified in the ``authorized_keys`` file. There is no interaction with the
    web UI.  Once SSH access is correctly configured and enabled, it will work
    regardless of whether the Kallithea web process is actually running. Hence,
    if you want to perform repository or server maintenance and want to fully
    disable all access to the repositories, disable SSH access by setting
    ``ssh_enabled = false`` in the correct ``.ini`` file (i.e. the ``.ini`` file
    specified in the ``authorized_keys`` file.)

The ``authorized_keys`` file can be updated manually with ``kallithea-cli
ssh-update-authorized-keys -c my.ini``. This command is not needed in normal
operation but is for example useful after changing SSH-related settings in the
``.ini`` file or renaming that file. (The path to the ``.ini`` file is used in
the generated ``authorized_keys`` file).


Setting up Whoosh full text search
----------------------------------

Kallithea provides full text search of repositories using `Whoosh`__.

.. __: https://whoosh.readthedocs.io/

For an incremental index build, run::

    kallithea-cli index-create -c my.ini

For a full index rebuild, run::

    kallithea-cli index-create -c my.ini --full

The ``--repo-location`` option allows the location of the repositories to be overridden;
usually, the location is retrieved from the Kallithea database.

The ``--index-only`` option can be used to limit the indexed repositories to a comma-separated list::

    kallithea-cli index-create -c my.ini --index-only=vcs,kallithea

To keep your index up-to-date it is necessary to do periodic index builds;
for this, it is recommended to use a crontab entry. Example::

    0  3  *  *  *  /path/to/virtualenv/bin/kallithea-cli index-create -c /path/to/kallithea/my.ini

When using incremental mode (the default), Whoosh will check the last
modification date of each file and add it to be reindexed if a newer file is
available. The indexing daemon checks for any removed files and removes them
from index.

If you want to rebuild the index from scratch, you can use the ``-f`` flag as above,
or in the admin panel you can check the "build from scratch" checkbox.


Integration with issue trackers
-------------------------------

Kallithea provides a simple integration with issue trackers. It's possible
to define a regular expression that will match an issue ID in commit messages,
and have that replaced with a URL to the issue.

This is achieved with following three variables in the ini file::

    issue_pat = #(\d+)
    issue_server_link = https://issues.example.com/{repo}/issue/\1
    issue_sub =

``issue_pat`` is the regular expression describing which strings in
commit messages will be treated as issue references. The expression can/should
have one or more parenthesized groups that can later be referred to in
``issue_server_link`` and ``issue_sub`` (see below). If you prefer, named groups
can be used instead of simple parenthesized groups.

If the pattern should only match if it is preceded by whitespace, add the
following string before the actual pattern: ``(?:^|(?<=\s))``.
If the pattern should only match if it is followed by whitespace, add the
following string after the actual pattern: ``(?:$|(?=\s))``.
These expressions use lookbehind and lookahead assertions of the Python regular
expression module to avoid the whitespace to be part of the actual pattern,
otherwise the link text will also contain that whitespace.

Matched issue references are replaced with the link specified in
``issue_server_link``, in which any backreferences are resolved. Backreferences
can be ``\1``, ``\2``, ... or for named groups ``\g<groupname>``.
The special token ``{repo}`` is replaced with the full repository path
(including repository groups), while token ``{repo_name}`` is replaced with the
repository name (without repository groups).

The link text is determined by ``issue_sub``, which can be a string containing
backreferences to the groups specified in ``issue_pat``. If ``issue_sub`` is
empty, then the text matched by ``issue_pat`` is used verbatim.

The example settings shown above match issues in the format ``#<number>``.
This will cause the text ``#300`` to be transformed into a link:

.. code-block:: html

  <a href="https://issues.example.com/example_repo/issue/300">#300</a>

The following example transforms a text starting with either of 'pullrequest',
'pull request' or 'PR', followed by an optional space, then a pound character
(#) and one or more digits, into a link with the text 'PR #' followed by the
digits::

    issue_pat = (pullrequest|pull request|PR) ?#(\d+)
    issue_server_link = https://issues.example.com/\2
    issue_sub = PR #\2

The following example demonstrates how to require whitespace before the issue
reference in order for it to be recognized, such that the text ``issue#123`` will
not cause a match, but ``issue #123`` will::

    issue_pat = (?:^|(?<=\s))#(\d+)
    issue_server_link = https://issues.example.com/\1
    issue_sub =

If needed, more than one pattern can be specified by appending a unique suffix to
the variables. For example, also demonstrating the use of named groups::

    issue_pat_wiki = wiki-(?P<pagename>\S+)
    issue_server_link_wiki = https://wiki.example.com/\g<pagename>
    issue_sub_wiki = WIKI-\g<pagename>

With these settings, wiki pages can be referenced as wiki-some-id, and every
such reference will be transformed into:

.. code-block:: html

  <a href="https://wiki.example.com/some-id">WIKI-some-id</a>

Refer to the `Python regular expression documentation`_ for more details about
the supported syntax in ``issue_pat``, ``issue_server_link`` and ``issue_sub``.


Hook management
---------------

Custom Mercurial hooks can be managed in a similar way to that used in ``.hgrc`` files.
To manage hooks, choose *Admin > Settings > Hooks*.

To add another custom hook simply fill in the first textbox with
``<name>.<hook_type>`` and the second with the hook path. Example hooks
can be found in ``kallithea.lib.hooks``.

Kallithea will also use some hooks internally. They cannot be modified, but
some of them can be enabled or disabled in the *VCS* section.

Kallithea does not actively support custom Git hooks, but hooks can be installed
manually in the file system. Kallithea will install and use the
``post-receive`` Git hook internally, but it will then invoke
``post-receive-custom`` if present.


Changing default encoding
-------------------------

By default, Kallithea uses UTF-8 encoding.
This is configurable as ``default_encoding`` in the .ini file.
This affects many parts in Kallithea including user names, filenames, and
encoding of commit messages. In addition Kallithea can detect if the ``chardet``
library is installed. If ``chardet`` is detected Kallithea will fallback to it
when there are encode/decode errors.

The Mercurial encoding is configurable as ``hgencoding``. It is similar to
setting the ``HGENCODING`` environment variable, but will override it.


Celery configuration
--------------------

Kallithea can use the distributed task queue system Celery_ to run tasks like
cloning repositories or sending emails.

Kallithea will in most setups work perfectly fine out of the box (without
Celery), executing all tasks in the web server process. Some tasks can however
take some time to run and it can be better to run such tasks asynchronously in
a separate process so the web server can focus on serving web requests.

For installation and configuration of Celery, see the `Celery documentation`_.
Note that Celery requires a message broker service like RabbitMQ_ (recommended)
or Redis_.

The use of Celery is configured in the Kallithea ini configuration file.
To enable it, simply set::

  use_celery = true

and add or change the ``celery.*`` configuration variables.

Configuration settings are prefixed with 'celery.', so for example setting
`broker_url` in Celery means setting `celery.broker_url` in the configuration
file.

To start the Celery process, run::

  kallithea-cli celery-run -c my.ini

Extra options to the Celery worker can be passed after ``--`` - see ``-- -h``
for more info.

.. note::
   Make sure you run this command from the same virtualenv, and with the same
   user that Kallithea runs.


Proxy setups
------------

When Kallithea is processing HTTP requests from a user, it will see and use
some of the basic properties of the connection, both at the TCP/IP level and at
the HTTP level. The WSGI server will provide this information to Kallithea in
the "environment".

In some setups, a proxy server will take requests from users and forward
them to the actual Kallithea server. The proxy server will thus be the
immediate client of the Kallithea WSGI server, and Kallithea will basically see
it as such. To make sure Kallithea sees the request as it arrived from the
client to the proxy server, the proxy server must be configured to
somehow pass the original information on to Kallithea, and Kallithea must be
configured to pick that information up and trust it.

Kallithea will by default rely on its WSGI server to provide the IP of the
client in the WSGI environment as ``REMOTE_ADDR``, but it can be configured to
get it from an HTTP header that has been set by the proxy server. For
example, if the proxy server puts the client IP in the ``X-Forwarded-For``
HTTP header, set::

    remote_addr_variable = HTTP_X_FORWARDED_FOR

Kallithea will by default rely on finding the protocol (``http`` or ``https``)
in the WSGI environment as ``wsgi.url_scheme``. If the proxy server puts
the protocol of the client request in the ``X-Forwarded-Proto`` HTTP header,
Kallithea can be configured to trust that header by setting::

    url_scheme_variable = HTTP_X_FORWARDED_PROTO


HTTPS support
-------------

Kallithea will by default generate URLs based on the WSGI environment.

Alternatively, you can use some special configuration settings to control
directly which scheme/protocol Kallithea will use when generating URLs:

- With ``url_scheme_variable`` set, the scheme will be taken from that HTTP
  header.
- With ``force_https = true``, the scheme will be seen as ``https``.
- With ``use_htsts = true``, Kallithea will set ``Strict-Transport-Security`` when using https.

.. _nginx_virtual_host:


Nginx virtual host example
--------------------------

Sample config for Nginx using proxy:

.. code-block:: nginx

    upstream kallithea {
        server 127.0.0.1:5000;
        # add more instances for load balancing
        #server 127.0.0.1:5001;
        #server 127.0.0.1:5002;
    }

    ## gist alias
    server {
       listen          443;
       server_name     gist.example.com;
       access_log      /var/log/nginx/gist.access.log;
       error_log       /var/log/nginx/gist.error.log;

       ssl on;
       ssl_certificate     gist.your.kallithea.server.crt;
       ssl_certificate_key gist.your.kallithea.server.key;

       ssl_session_timeout 5m;

       ssl_protocols SSLv3 TLSv1;
       ssl_ciphers DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA:DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5;
       ssl_prefer_server_ciphers on;

       rewrite ^/(.+)$ https://kallithea.example.com/_admin/gists/$1;
       rewrite (.*)    https://kallithea.example.com/_admin/gists;
    }

    server {
       listen          443;
       server_name     kallithea.example.com
       access_log      /var/log/nginx/kallithea.access.log;
       error_log       /var/log/nginx/kallithea.error.log;

       ssl on;
       ssl_certificate     your.kallithea.server.crt;
       ssl_certificate_key your.kallithea.server.key;

       ssl_session_timeout 5m;

       ssl_protocols SSLv3 TLSv1;
       ssl_ciphers DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA:AES256-SHA:DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5;
       ssl_prefer_server_ciphers on;

       ## uncomment root directive if you want to serve static files by nginx
       ## requires static_files = false in .ini file
       #root /srv/kallithea/kallithea/kallithea/public;
       include         /etc/nginx/proxy.conf;
       location / {
            try_files $uri @kallithea;
       }

       location @kallithea {
            proxy_pass      http://127.0.0.1:5000;
       }

    }

Here's the proxy.conf. It's tuned so it will not timeout on long
pushes or large pushes::

    proxy_redirect              off;
    proxy_set_header            Host $host;
    ## needed for container auth
    #proxy_set_header            REMOTE_USER $remote_user;
    #proxy_set_header            X-Forwarded-User $remote_user;
    proxy_set_header            X-Url-Scheme $scheme;
    proxy_set_header            X-Host $http_host;
    proxy_set_header            X-Real-IP $remote_addr;
    proxy_set_header            X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header            Proxy-host $proxy_host;
    proxy_buffering             off;
    proxy_connect_timeout       7200;
    proxy_send_timeout          7200;
    proxy_read_timeout          7200;
    proxy_buffers               8 32k;
    client_max_body_size        1024m;
    client_body_buffer_size     128k;
    large_client_header_buffers 8 64k;

.. _apache_virtual_host_reverse_proxy:


Apache virtual host reverse proxy example
-----------------------------------------

Here is a sample configuration file for Apache using proxy:

.. code-block:: apache

    <VirtualHost *:80>
            ServerName kallithea.example.com

            <Proxy *>
              # For Apache 2.4 and later:
              Require all granted

              # For Apache 2.2 and earlier, instead use:
              # Order allow,deny
              # Allow from all
            </Proxy>

            #important !
            #Directive to properly generate url (clone url) for Kallithea
            ProxyPreserveHost On

            #kallithea instance
            ProxyPass / http://127.0.0.1:5000/
            ProxyPassReverse / http://127.0.0.1:5000/

            #to enable https use line below
            #SetEnvIf X-Url-Scheme https HTTPS=1
    </VirtualHost>

Additional tutorial
http://pylonsbook.com/en/1.1/deployment.html#using-apache-to-proxy-requests-to-pylons

.. _apache_subdirectory:


Apache as subdirectory
----------------------

Apache subdirectory part:

.. code-block:: apache

    <Location /PREFIX >
      ProxyPass http://127.0.0.1:5000/PREFIX
      ProxyPassReverse http://127.0.0.1:5000/PREFIX
      SetEnvIf X-Url-Scheme https HTTPS=1
    </Location>

Besides the regular apache setup you will need to add the following line
into ``[app:main]`` section of your .ini file::

    filter-with = proxy-prefix

Add the following at the end of the .ini file::

    [filter:proxy-prefix]
    use = egg:PasteDeploy#prefix
    prefix = /PREFIX

then change ``PREFIX`` into your chosen prefix

.. _apache_mod_wsgi:


Apache with mod_wsgi
--------------------

Alternatively, Kallithea can be set up with Apache under mod_wsgi. For
that, you'll need to:

- Install mod_wsgi. If using a Debian-based distro, you can install
  the package libapache2-mod-wsgi::

    aptitude install libapache2-mod-wsgi

- Enable mod_wsgi::

    a2enmod wsgi

- Add global Apache configuration to tell mod_wsgi that Python only will be
  used in the WSGI processes and shouldn't be initialized in the Apache
  processes::

    WSGIRestrictEmbedded On

- Create a WSGI dispatch script, like the one below. The ``WSGIDaemonProcess``
  ``python-home`` directive will make sure it uses the right Python Virtual
  Environment and that paste thus can pick up the right Kallithea
  application.

  .. code-block:: python

      ini = '/srv/kallithea/my.ini'
      from logging.config import fileConfig
      fileConfig(ini, {'__file__': ini, 'here': '/srv/kallithea'})
      from paste.deploy import loadapp
      application = loadapp('config:' + ini)

- Add the necessary ``WSGI*`` directives to the Apache Virtual Host configuration
  file, like in the example below. Notice that the WSGI dispatch script created
  above is referred to with the ``WSGIScriptAlias`` directive.
  The default locale settings Apache provides for web services are often not
  adequate, with `C` as the default language and `ASCII` as the encoding.
  Instead, use the ``lang`` parameter of ``WSGIDaemonProcess`` to specify a
  suitable locale. See also the :ref:`overview` section and the
  `WSGIDaemonProcess documentation`_.

  Apache will by default run as a special Apache user, on Linux systems
  usually ``www-data`` or ``apache``. If you need to have the repositories
  directory owned by a different user, use the user and group options to
  WSGIDaemonProcess to set the name of the user and group.

  Once again, check that all paths are correctly specified.

  .. code-block:: apache

      WSGIDaemonProcess kallithea processes=5 threads=1 maximum-requests=100 \
          python-home=/srv/kallithea/venv lang=C.UTF-8
      WSGIProcessGroup kallithea
      WSGIScriptAlias / /srv/kallithea/dispatch.wsgi
      WSGIPassAuthorization On


Other configuration files
-------------------------

A number of `example init.d scripts`__ can be found in
the ``init.d`` directory of the Kallithea source.

.. __: https://kallithea-scm.org/repos/kallithea/files/tip/init.d/ .


.. _python: http://www.python.org/
.. _Python regular expression documentation: https://docs.python.org/2/library/re.html
.. _Mercurial: https://www.mercurial-scm.org/
.. _Celery: http://celeryproject.org/
.. _Celery documentation: http://docs.celeryproject.org/en/latest/getting-started/index.html
.. _RabbitMQ: http://www.rabbitmq.com/
.. _Redis: http://redis.io/
.. _mercurial-server: http://www.lshift.net/mercurial-server.html
.. _PublishingRepositories: https://www.mercurial-scm.org/wiki/PublishingRepositories
.. _WSGIDaemonProcess documentation: https://modwsgi.readthedocs.io/en/develop/configuration-directives/WSGIDaemonProcess.html
