import os
import time

from celery.task import periodic_task
from celery.task.schedules import crontab
from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, connections
from django.db.migrations.executor import MigrationExecutor
from fabric.api import local


def is_database_synchronized(database):
    connection = connections[database]
    connection.prepare_database()
    executor = MigrationExecutor(connection)
    targets = executor.loader.graph.leaf_nodes()
    return False if executor.migration_plan(targets) else True


def generate_backup(fname, command, is_deploy):
    day_fname = None
    week_fname = None

    if not is_deploy:
        day = time.strftime('%w')
        week = ((int(time.strftime('%d')) - 1) // 7) + 1

        day_fname = fname.replace('%name%', 'day-{}'.format(day))
        week_fname = fname.replace('%name%', 'week-{}'.format(week))
    else:
        day_fname = fname.replace('%name%', 'deploy-{}'.format(time.strftime('%Y%m%d%H')))

    local('{command} | gzip > {fname}'.format(command=command, fname=day_fname))

    if not is_deploy:
        local('cp {day_fname} {week_fname}'.format(day_fname=day_fname, week_fname=week_fname))
    else:
        files = local('ls -r {names}*'.format(names=day_fname.split('-')[0]), capture=True)
        for file in files.split('\n')[3:]:
            local('rm {file}'.format(file=file))

    return [day_fname, week_fname, is_deploy]


@periodic_task(run_every=crontab(minute=0, hour=1))
def backup_postgres(is_deploy=False):

    if is_deploy and is_database_synchronized(DEFAULT_DB_ALIAS):
        print('is_database_synchronized')
        return 'is_database_synchronized'

    folder = '{}/backups'.format(settings.BASE_DIR)
    local('mkdir -p {folder}/postgres'.format(folder=folder))

    fname = '{folder}/postgres/%name%.backup.gzip'.format(folder=folder)
    command = 'export PGPASSWORD={password} && pg_dumpall --host=postgres --username={user}'.format(
        password=os.environ.get('POSTGRES_PASSWORD'), user=os.environ.get('POSTGRES_USER')
    )

    return generate_backup(fname, command, is_deploy)
