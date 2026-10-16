"""Celery application: Redis broker + result backend for background scan jobs.

Per-task retry policy (max_retries=3, retry_backoff=True) is set on the task
itself in api/tasks/scan_task.py, which is where Celery expects it — this
module only carries the app-wide broker/serialization config.
"""

from celery import Celery

from api.config import get_settings

_settings = get_settings()

celery_app = Celery(
    "secretsweep",
    broker=_settings.redis_url,
    backend=_settings.redis_url,
    # Without this, `celery -A api.celery_app worker` never imports the module that
    # defines @celery_app.task(name="run_scan_task") (api/tasks/scan_task.py), so the
    # task decorator never runs and the worker rejects every dispatched scan job as
    # "unregistered" — it just sits at PENDING forever. `include`, not a module-level
    # `import api.tasks.scan_task` here, because scan_task.py imports celery_app FROM
    # this module — a direct import would be circular.
    include=["api.tasks.scan_task"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    task_track_started=True,
    # Fail fast instead of retrying for several seconds when the broker is
    # unreachable — dispatch is already run off the event loop (see
    # api/routes/scan.py), but a slow failure there still ties up a thread
    # and delays the "queued" outcome longer than it needs to.
    broker_connection_retry_on_startup=False,
    task_publish_retry=False,
)
