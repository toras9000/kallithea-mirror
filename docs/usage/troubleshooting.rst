.. _troubleshooting:

===============
Troubleshooting
===============

:Q: **Missing static files?**
:A: Make sure either to set the ``static_files = true`` in the .ini file or
   double check the root path for your http setup. It should point to
   for example:
   ``/home/my-virtual-python/lib/python3.7/site-packages/kallithea/public``

|

:Q: **Can't install celery/rabbitmq?**
:A: Don't worry. Kallithea works without them, too. No extra setup is required.
    Try out the great Celery docs for further help.

|

:Q: **Long lasting push timeouts?**
:A: Make sure you set a longer timeout in your proxy/fcgi settings. Timeouts
    are caused by the http server and not Kallithea.

|

:Q: **Large pushes timeouts?**
:A: Make sure you set a proper ``max_body_size`` for the http server. Very often
    Apache, Nginx, or other http servers kill the connection due to to large
    body.

|

:Q: **Apache doesn't pass basicAuth on pull/push?**
:A: Make sure you added ``WSGIPassAuthorization true``.

|

:Q: **Git fails on push/pull?**
:A: Make sure you're using a WSGI http server that can handle chunked encoding
    such as ``waitress`` or ``gunicorn``.

|

:Q: **How can I use hooks in Kallithea?**
:A: If using Mercurial, use *Admin > Settings > Hooks* to install
    global hooks. Inside the hooks, you can use the current working directory to
    control different behaviour for different repositories.

    If using Git, install the hooks manually in each repository, for example by
    creating a file ``gitrepo/hooks/pre-receive``.
    Note that Kallithea uses the ``post-receive`` hook internally.
    Kallithea will not work properly if another post-receive hook is installed instead.
    You might also accidentally overwrite your own post-receive hook with the Kallithea hook.
    Instead, put your post-receive hook in ``post-receive-custom``, and the Kallithea hook will invoke it.

    You can also use Kallithea-extensions to connect to callback hooks,
    for both Git and Mercurial.

|

:Q: **Kallithea is slow for me, how can I make it faster?**
:A: See the :ref:`performance` section.

|

:Q: **UnicodeDecodeError on Apache mod_wsgi**
:A: Please read: https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/modwsgi/#if-you-get-a-unicodeencodeerror.

|

:Q: **Requests hanging on Windows**
:A: Please try out with disabled Antivirus software, there are some known problems with Eset Antivirus. Make sure
    you have installed the latest Windows patches (especially KB2789397).


.. _python: http://www.python.org/
.. _mercurial: https://www.mercurial-scm.org/
.. _celery: http://celeryproject.org/
.. _rabbitmq: http://www.rabbitmq.com/
.. _python-ldap: http://www.python-ldap.org/
