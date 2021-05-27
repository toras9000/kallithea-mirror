#!/usr/bin/env python3


import re
import sys


ignored_modules = set('''
argparse
base64
bcrypt
binascii
bleach
calendar
celery
celery
chardet
click
collections
configparser
copy
csv
ctypes
datetime
dateutil
decimal
decorator
difflib
distutils
docutils
email
errno
fileinput
functools
getpass
grp
hashlib
hmac
html
http
imp
importlib
inspect
io
ipaddr
IPython
isapi_wsgi
itertools
json
kajiki
ldap
logging
mako
markdown
mimetypes
mock
msvcrt
multiprocessing
operator
os
paginate
paginate_sqlalchemy
pam
paste
pkg_resources
platform
posixpath
pprint
pwd
pyflakes
pytest
pytest_localserver
random
re
routes
setuptools
shlex
shutil
smtplib
socket
ssl
stat
string
struct
subprocess
sys
tarfile
tempfile
textwrap
tgext
threading
time
traceback
traitlets
types
typing
urllib
urlobject
uuid
warnings
webhelpers2
webob
webtest
whoosh
win32traceutil
zipfile
'''.split())

top_modules = set('''
kallithea.alembic
kallithea.bin
kallithea.config
kallithea.controllers
kallithea.templates.py
scripts
'''.split())

bottom_external_modules = set('''
tg
mercurial
sqlalchemy
alembic
formencode
pygments
dulwich
beaker
psycopg2
docs
setup
conftest
'''.split())

normal_modules = set('''
kallithea
kallithea.controllers.base
kallithea.lib
kallithea.lib.auth
kallithea.lib.auth_modules
kallithea.lib.celerylib
kallithea.lib.db_manage
kallithea.lib.helpers
kallithea.lib.hooks
kallithea.lib.indexers
kallithea.lib.utils
kallithea.lib.utils2
kallithea.lib.vcs
kallithea.lib.webutils
kallithea.model
kallithea.model.async_tasks
kallithea.model.scm
kallithea.templates.py
'''.split())

shown_modules = normal_modules | top_modules

# break the chains somehow - this is a cleanup TODO list
known_violations = set([
('kallithea.lib.auth_modules', 'kallithea.lib.auth'),  # needs base&facade
('kallithea.lib.utils', 'kallithea.model'),  # clean up utils
('kallithea.lib.utils', 'kallithea.model.db'),
('kallithea.lib.utils', 'kallithea.model.scm'),
('kallithea.model', 'kallithea.lib.auth'),  # auth.HasXXX
('kallithea.model', 'kallithea.lib.auth_modules'),  # validators
('kallithea.model', 'kallithea.lib.hooks'),  # clean up hooks
('kallithea.model', 'kallithea.model.scm'),
('kallithea.model.scm', 'kallithea.lib.hooks'),
])

extra_edges = [
('kallithea.config', 'kallithea.controllers'),  # through TG
('kallithea.lib.auth', 'kallithea.lib.auth_modules'),  # custom loader
]


def normalize(s):
    """Given a string with dot path, return the string it should be shown as."""
    parts = s.replace('.__init__', '').split('.')
    short_2 = '.'.join(parts[:2])
    short_3 = '.'.join(parts[:3])
    short_4 = '.'.join(parts[:4])
    if parts[0] in ['scripts', 'contributor_data', 'i18n_utils']:
        return 'scripts'
    if short_3 == 'kallithea.model.meta':
        return 'kallithea.model.db'
    if parts[:4] == ['kallithea', 'lib', 'vcs', 'ssh']:
        return 'kallithea.lib.vcs.ssh'
    if short_4 in shown_modules:
        return short_4
    if short_3 in shown_modules:
        return short_3
    if short_2 in shown_modules:
        return short_2
    if short_2 == 'kallithea.tests':
        return None
    if parts[0] in ignored_modules:
        return None
    assert parts[0] in bottom_external_modules, parts
    return parts[0]


def main(filenames):
    if not filenames or filenames[0].startswith('-'):
        print('''\
Usage:
    hg files 'set:!binary()&grep("^#!.*python")' 'set:**.py' | xargs scripts/deps.py
    dot -Tsvg deps.dot > deps.svg
        ''')
        raise SystemExit(1)

    files_imports = dict()  # map filenames to its imports
    import_deps = set()  # set of tuples with module name and its imports
    for fn in filenames:
        with open(fn) as f:
            s = f.read()

        dot_name = (fn[:-3] if fn.endswith('.py') else fn).replace('/', '.')
        file_imports = set()
        for m in re.finditer(r'^ *(?:from ([^ ]*) import (?:([a-zA-Z].*)|\(([^)]*)\))|import (.*))$', s, re.MULTILINE):
            m_from, m_from_import, m_from_import2, m_import = m.groups()
            if m_from:
                pre = m_from + '.'
                if pre.startswith('.'):
                    pre = dot_name.rsplit('.', 1)[0] + pre
                importlist = m_from_import or m_from_import2
            else:
                pre = ''
                importlist = m_import
            for imp in importlist.split('#', 1)[0].split(','):
                full_imp = pre + imp.strip().split(' as ', 1)[0]
                file_imports.add(full_imp)
                import_deps.add((dot_name, full_imp))
        files_imports[fn] = file_imports

    # dump out all deps for debugging and analysis
    with open('deps.txt', 'w') as f:
        for fn, file_imports in sorted(files_imports.items()):
            for file_import in sorted(file_imports):
                if file_import.split('.', 1)[0] in ignored_modules:
                    continue
                f.write('%s: %s\n' % (fn, file_import))

    # find leafs that haven't been ignored - they are the important external dependencies and shown in the bottom row
    only_imported = set(
        set(normalize(b) for a, b in import_deps) -
        set(normalize(a) for a, b in import_deps) -
        set([None, 'kallithea'])
    )

    normalized_dep_edges = set()
    for dot_name, full_imp in import_deps:
        a = normalize(dot_name)
        b = normalize(full_imp)
        if a is None or b is None or a == b:
            continue
        normalized_dep_edges.add((a, b))
        #print((dot_name, full_imp, a, b))
    normalized_dep_edges.update(extra_edges)

    unseen_shown_modules = shown_modules.difference(a for a, b in normalized_dep_edges).difference(b for a, b in normalized_dep_edges)
    assert not unseen_shown_modules, unseen_shown_modules

    with open('deps.dot', 'w') as f:
        f.write('digraph {\n')
        f.write('subgraph { rank = same; %s}\n' % ''.join('"%s"; ' % s for s in sorted(top_modules)))
        f.write('subgraph { rank = same; %s}\n' % ''.join('"%s"; ' % s for s in sorted(only_imported)))
        for a, b in sorted(normalized_dep_edges):
            f.write('  "%s" -> "%s"%s\n' % (a, b, ' [color=red]' if (a, b) in known_violations else ' [color=green]' if (a, b) in extra_edges else ''))
        f.write('}\n')

    # verify dependencies by untangling dependency chain bottom-up:
    todo = set(normalized_dep_edges)
    unseen_violations = known_violations.difference(todo)
    assert not unseen_violations, unseen_violations
    for x in known_violations:
        todo.remove(x)

    while todo:
        depending = set(a for a, b in todo)
        depended = set(b for a, b in todo)
        drop = depended - depending
        if not drop:
            print('ERROR: cycles:', len(todo))
            for x in sorted(todo):
                print('%s,' % (x,))
            raise SystemExit(1)
        #for do_b in sorted(drop):
        #    print('Picking', do_b, '- unblocks:', ' '.join(a for a, b in sorted((todo)) if b == do_b))
        todo = set((a, b) for a, b in todo if b in depending)
        #print()


if __name__ == '__main__':
    main(sys.argv[1:])
