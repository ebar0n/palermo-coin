# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os

from celery import Celery
from django.conf import settings
# from opbeat.contrib.celery import register_signal
# from opbeat.contrib.django.models import client, logger, register_handlers

# set the default Django settings module for the 'celery' program.
if not settings.configured:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'api.settings')

# set the default Django settings module for the 'celery' program.
app = Celery('api', include=['utils.tasks.emails', 'api.tasks'])

app.config_from_object('api.celeryconfig')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


# try:
#     register_signal(client)
# except Exception as e:
#     logger.exception('Failed installing celery hook: %s' % e)

# if 'opbeat.contrib.django' in settings.INSTALLED_APPS:
#     register_handlers()
