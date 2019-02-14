
from api import tasks


def run():
    """
    fab command:cmd="runscript backups"
    """
    tasks.backup_postgres(is_deploy=True)
