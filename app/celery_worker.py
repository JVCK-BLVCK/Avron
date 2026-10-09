"""
    Celery task worker — replaces spawn_background_task for scan execution.

    Why Celery over asyncio background tasks?

    asyncio.create_task() (current):
    - Lives in the FastAPI process memory
    - Killed if the server restarts
    - No retry on failure
    - No visibility into what's running
    - No queue depth metrics

    Celery + Redis (Phase 5):
    - Task lives in Redis — survives server restart
    - Worker is a separate process — can be scaled independently
    - Automatic retry on failure with configurable backoff
    - Full task history and result tracking
    - Queue depth visible for scaling decisions

    The trade: more infrastructure complexity for much better reliability.
    This trade is correct for production — unacceptable for an MVP,
    correct once you have users depending on results.
"""
from app.config import settings
import logging
from celery import Celery

logger = logging.getLogger(__name__)

REDIS_URL = settings.redis_url

# Configure Celery Application
# The broker is where Celery sends tasks to be executed.
# The backend is where Celery stores the results of tasks.
celery_app = Celery(
    "avron",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

# Configure Celery to use JSON serialization for tasks and results
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Retry failed tasks up to 3 times with exponential backoff
    task_acks_late=True,   # acknowledge after completion not on receipt
    task_reject_on_worker_lost=True,    # re-queue if worker dies mid-task
)

@celery_app.task(
    name="avron.run_scan",
    bind=True,
    max_retries=3,
    default_retry_delay=30,  # Retry after 30 seconds
)

def run_scan_task(self, scan_id: str, target_url: str) -> None:
    """
    Celery task to run a Nuclei scan. This function is executed in a separate worker process.

    bind=True gives access to self (the task instance) for retries.
    max_retries=2 means 3 total attempts (original + 2 retries).
    default_retry_delay=30 waits 30 seconds between retries.

    Why retries?
    Network conditions are transient. A scan that fails because
    of a momentary DNS resolution failure should retry — not
    permanently fail and require manual intervention. 

    """
    from app.scanner import run_nuclei

    logger.info({
        "event": "Celery_task_started",
        "scan_id": scan_id,
        "target_url": target_url,
        "task_id": self.request.id,
    })

    try:
        # Run the Nuclei scan (this is a blocking call)
        # If it raises an exception, Celery will catch it and retry the task.
        run_nuclei(scan_id, target_url)
    except Exception as exc:
        logger.error({
            "event": "Celery_task_failed",
            "scan_id": scan_id,
            "target_url": target_url,
            "task_id": self.request.id,
            "error": str(exc),
            "retries": self.request.retries,
        })
        # Retry the task with exponential backoff
        raise self.retry(exc=exc, countdown=30 * (2 ** self.request.retries))
    
