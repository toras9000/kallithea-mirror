.. _installation:

==========================
Installation on Unix/Linux
==========================

The following describes three different ways of installing Kallithea:

- :ref:`installation-source`: The simplest way to keep the installation
  up-to-date and track any local customizations is to run directly from
  source in a Kallithea repository clone, preferably inside a virtualenv
  virtual Python environment.

- :ref:`installation-virtualenv`: If you prefer to only use released versions
  of Kallithea, the recommended method is to install Kallithea in a virtual
  Python environment using `virtualenv`. The advantages of this method over
  direct installation is that Kallithea and its dependencies are completely
  contained inside the virtualenv (which also means you can have multiple
  installations side by side or remove it entirely by just removing the
  virtualenv directory) and does not require root privileges.

- Kallithea can also be installed with plain pip - globally or with ``--user``
  or similar. The package will be installed in the same location as all other
  Python packages you have ever installed. As a result, removing it is not as
  straightforward as with a virtualenv, as you'd have to remove its
  dependencies manually and make sure that they are not needed by other
  packages. We recommend using virtualenv.

Regardless of the installation method you may need to make sure you have
appropriate development packages installed, as installation of some of the
Kallithea dependencies requires a working C compiler and libffi library
headers. Depending on your configuration, you may also need to install
Git and development packages for the database of your choice.

For Debian and Ubuntu, the following command will ensure that a reasonable
set of dependencies is installed::

    sudo apt-get install build-essential git libffi-dev python3-dev

For Fedora and RHEL-derivatives, the following command will ensure that a
reasonable set of dependencies is installed::

    sudo yum install gcc git libffi-devel python3-devel

.. _installation-source:


Installation from repository source
-----------------------------------

To install Kallithea in a virtualenv using the stable branch of the development
repository, use the following commands in your bash shell::

        hg clone https://kallithea-scm.org/repos/kallithea -u stable
        cd kallithea
        python3 -m venv venv
        . venv/bin/activate
        pip install --upgrade pip setuptools
        pip install --upgrade -e .
        python3 setup.py compile_catalog   # for translation of the UI

.. note::
   This will install all Python dependencies into the virtualenv. Kallithea
   itself will however only be installed as a pointer to the source location.
   The source clone must thus be kept in the same location, and it shouldn't be
   updated to other revisions unless you want to upgrade. Edits in the source
   tree will have immediate impact (possibly after a restart of the service).

You can now proceed to :ref:`prepare-front-end-files`.

.. _installation-virtualenv:


Installing a released version in a virtualenv
---------------------------------------------

It is highly recommended to use a separate virtualenv for installing Kallithea.
This way, all libraries required by Kallithea will be installed separately from your
main Python installation and other applications and things will be less
problematic when upgrading the system or Kallithea.
An additional benefit of virtualenv is that it doesn't require root privileges.

- Don't install as root - install as a dedicated user like ``kallithea``.
  If necessary, create the top directory for the virtualenv (like
  ``/srv/kallithea/venv``) as root and assign ownership to the user.

  Make a parent folder for the virtualenv (and perhaps also Kallithea
  configuration and data files) such as ``/srv/kallithea``. Create the
  directory as root if necessary and grant ownership to the ``kallithea`` user.

- Create a new virtual environment, for example in ``/srv/kallithea/venv``,
  specifying the right Python binary::

    python3 -m venv /srv/kallithea/venv

- Activate the virtualenv in your current shell session and make sure the
  basic requirements are up-to-date by running the following commands in your
  bash shell::

    . /srv/kallithea/venv/bin/activate
    pip install --upgrade pip setuptools

.. note:: You can't use UNIX ``sudo`` to source the ``activate`` script; it
   will "activate" a shell that terminates immediately.

- Install Kallithea in the activated virtualenv::

    pip install --upgrade kallithea

.. note:: Some dependencies are optional. If you need them, install them in
   the virtualenv too::

     pip install --upgrade kallithea python-ldap python-pam psycopg2

   This might require installation of development packages using your
   distribution's package manager.

   Alternatively, download a .tar.gz from http://pypi.python.org/pypi/Kallithea,
   extract it and install from source by running::

     pip install --upgrade .

- This will install Kallithea together with all other required
  Python libraries into the activated virtualenv.

You can now proceed to :ref:`prepare-front-end-files`.

.. _prepare-front-end-files:


Prepare front-end files
-----------------------

Finally, the front-end files with CSS and JavaScript must be prepared. This
depends on having some commands available in the shell search path: ``npm``
version 6 or later, and ``node.js`` (version 12 or later) available as
``node``. The installation method for these dependencies varies between
operating systems and distributions.

Prepare the front-end by running::

    kallithea-cli front-end-build

You can now proceed to :ref:`setup`.
