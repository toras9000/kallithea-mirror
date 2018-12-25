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

import click
import kallithea.bin.kallithea_cli_base as cli_base

import os
import subprocess
import json

import kallithea

@cli_base.register_command()
@click.option('--install-deps/--no-install-deps', default=True,
        help='Skip installation of dependencies, via "npm".')
@click.option('--generate/--no-generate', default=True,
        help='Skip generation of front-end files.')
def front_end_build(install_deps, generate):
    """Build the front-end.

    Install required dependencies for the front-end and generate the necessary
    files.  This step is complementary to any 'pip install' step which only
    covers Python dependencies.

    The installation of front-end dependencies happens via the tool 'npm' which
    is expected to be installed already.
    """
    front_end_dir = os.path.abspath(os.path.join(kallithea.__file__, '..', 'front-end'))
    public_dir = os.path.abspath(os.path.join(kallithea.__file__, '..', 'public'))

    if install_deps:
        click.echo("Running 'npm install' to install front-end dependencies from package.json")
        subprocess.check_call(['npm', 'install'], cwd=front_end_dir)

    if generate:
        tmp_dir = os.path.join(front_end_dir, 'tmp')
        if not os.path.isdir(tmp_dir):
            os.mkdir(tmp_dir)

        click.echo("Generating CSS")
        with open(os.path.join(tmp_dir, 'pygments.css'), 'w') as f:
            subprocess.check_call(['pygmentize',
                    '-S', 'default',
                    '-f', 'html',
                    '-a', '.code-highlight'],
                    stdout=f)
        lesscpath = os.path.join(front_end_dir, 'node_modules', '.bin', 'lessc')
        lesspath = os.path.join(public_dir, 'less', 'main.less')
        csspath = os.path.join(public_dir, 'css', 'style.css')
        subprocess.check_call([lesscpath, '--relative-urls', '--source-map',
                '--source-map-less-inline', lesspath, csspath],
                cwd=front_end_dir)

        click.echo("Generating LICENSES.txt")
        check_licensing_json_path = os.path.join(tmp_dir, 'licensing.json')
        licensing_txt_path = os.path.join(public_dir, 'LICENSES.txt')
        subprocess.check_call([
            os.path.join(front_end_dir, 'node_modules', '.bin', 'license-checker'),
            '--json',
            '--out', check_licensing_json_path,
            ], cwd=front_end_dir)
        with open(check_licensing_json_path) as jsonfile:
            rows = json.loads(jsonfile.read())
            with open(licensing_txt_path, 'w') as out:
                out.write("The Kallithea front-end was built using the following Node modules:\n\n")
                for name_version, values in sorted(rows.items()):
                    name, version = name_version.rsplit('@', 1)
                    line = "%s from https://www.npmjs.com/package/%s/v/%s\n  License: %s\n  Repository: %s\n" % (
                        name_version, name, version, values['licenses'], values.get('repository', '-'))
                    if values.get('copyright'):
                        line += "  Copyright: %s\n" % (values['copyright'])
                    out.write(line + '\n')
