#!/usr/bin/env python3

# hg files 'set:!binary()&grep("^#!.*python")' 'set:**.py' | xargs scripts/source_format.py

import re
import sys


filenames = sys.argv[1:]

for fn in filenames:
    with open(fn) as f:
        org_content = f.read()

    mod_name = fn[:-3] if fn.endswith('.py') else fn
    mod_name = mod_name[:-9] if mod_name.endswith('/__init__') else mod_name
    mod_name = mod_name.replace('/', '.')
    def f(m):
        return '"""\n%s\n%s\n' % (mod_name, '~' * len(mod_name))
    new_content = re.sub(r'^"""\n(kallithea\..*\n)(~+\n)?', f, org_content, count=1, flags=re.MULTILINE)

    if new_content != org_content:
        with open(fn, 'w') as f:
            f.write(new_content)
