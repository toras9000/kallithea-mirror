# -*- coding: utf-8 -*-

"""
Kallithea wrapper of Celery

The Celery configuration is in the Kallithea ini file but must be converted to an
entirely different format before Celery can use it.

We read the configuration from tg.config at module import time. This module can
thus not be imported in global scope but must be imported on demand in function
scope after tg.config has been initialized.

To make sure that the config really has been initialized, we check one of the
mandatory settings.
"""

import logging


class CeleryConfig(object):
    imports = [
        'kallithea.lib.indexers.daemon',
        'kallithea.model.async_tasks',
        'kallithea.model.notification',
        'kallithea.model.repo',
    ]
    task_always_eager = False

list_config_names = {'imports', 'accept_content'}


desupported = set([
    'broker.url',
    'celery.accept.content',
    'celery.always.eager',
    'celery.amqp.task.result.expires',
    'celeryd.concurrency',
    'celeryd.max.tasks.per.child',
    'celery.result.backend',  # Note: the .ini template used this instead of 'celery.result_backend' in 0.6
    'celery.result.dburi',
    'celery.result.serialier',
    'celery.result.serializer',
    'celery.send.task.error.emails',
    'celery.task_always_eager',  # still a valid configuration in celery, but not supported in Kallithea
    'celery.task.serializer',
])


log = logging.getLogger(__name__)


def make_celery_config(config):
    """Return Celery config object populated from relevant settings in a config dict, such as tg.config"""

    celery_config = CeleryConfig()

    for config_key, config_value in sorted(config.items()):
        if config_key in desupported and config_value:
            log.error('Celery configuration setting %r is no longer supported', config_key)
        parts = config_key.split('.', 1)
        if parts[0] == 'celery' and len(parts) == 2:  # Celery 4 config key
            celery_key = parts[1]
        else:
            continue
        if not isinstance(config_value, str):
            continue
        if celery_key in list_config_names:
            celery_value = config_value.split()
        elif config_value.isdigit():
            celery_value = int(config_value)
        elif config_value.lower() in ['true', 'false']:
            celery_value = config_value.lower() == 'true'
        else:
            celery_value = config_value
        setattr(celery_config, celery_key, celery_value)
    return celery_config
