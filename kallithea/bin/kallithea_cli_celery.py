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
from celery.bin.celery import celery as celery_command

import kallithea
import kallithea.bin.kallithea_cli_base as cli_base
from kallithea.lib import celery_app
from kallithea.lib.utils2 import asbool


@cli_base.register_command(needs_config_file=True)
@click.argument('celery_args', nargs=-1)
def celery_run(celery_args, config):
    """Start Celery worker(s) for asynchronous tasks.

    This commands starts the Celery daemon which will spawn workers to handle
    certain asynchronous tasks for Kallithea.

    Any extra arguments you pass to this command will be passed through to
    Celery. Use '--' before such extra arguments to avoid options to be parsed
    by this CLI command.
    """

    if not asbool(config.get('use_celery')):
        raise Exception('Please set use_celery = true in .ini config '
                        'file before running this command')

    kallithea.CELERY_APP.config_from_object(celery_app.make_celery_config(config))

    kallithea.CELERY_APP.loader.on_worker_process_init = lambda: kallithea.config.application.make_app(config.global_conf, **config.local_conf)

    args = list(celery_args)
    # args[0] is generally ignored when prog_name is specified, but -h *needs* it to be 'worker' ... but will also suggest that users specify 'worker' explicitly
    if not args or args[0] != 'worker':
        args.insert(0, 'worker')

    # inline kallithea.CELERY_APP.start in order to allow specifying prog_name
    assert celery_command.params[0].name == 'app'
    celery_command.params[0].default = kallithea.CELERY_APP
    celery_command.main(args=args, prog_name='kallithea-cli celery-run -c CONFIG_FILE --')
