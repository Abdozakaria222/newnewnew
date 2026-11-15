"""Background job runner: keeps the UI responsive, supports cancellation and
progress reporting. Only one heavy network job runs at a time to avoid
excessive traffic and skewed measurements."""
from __future__ import annotations

import logging
import threading
import time
import traceback
import uuid
from typing import Callable, Optional

log = logging.getLogger("netopt.jobs")


class Cancelled(Exception):
    pass


class JobContext:
    def __init__(self, job: "Job"):
        self._job = job

    @property
    def cancelled(self) -> bool:
        return self._job.cancel_event.is_set()

    def check(self) -> None:
        if self.cancelled:
            raise Cancelled()

    def progress(self, fraction: float, message: str = "") -> None:
        self._job.progress = max(0.0, min(1.0, fraction))
        if message:
            self._job.message = message
        self.check()

    def sleep(self, seconds: float) -> None:
        if self._job.cancel_event.wait(seconds):
            raise Cancelled()


class Job:
    def __init__(self, kind: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.state = "running"           # running / done / error / cancelled
        self.progress = 0.0
        self.message = ""
        self.result = None
        self.error = ""
        self.started = time.time()
        self.finished: Optional[float] = None
        self.cancel_event = threading.Event()

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "state": self.state,
                "progress": round(self.progress, 3), "message": self.message,
                "result": self.result if self.state == "done" else None,
                "error": self.error, "started": self.started, "finished": self.finished}


class JobManager:
    HEAVY = {"dns", "mtu", "workflow", "compare_before", "compare_after", "packet_loss"}

    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def busy_heavy(self) -> Optional[Job]:
        with self._lock:
            for j in self._jobs.values():
                if j.state == "running" and j.kind in self.HEAVY:
                    return j
        return None

    def start(self, kind: str, fn: Callable[[JobContext], object]) -> Job:
        if kind in self.HEAVY:
            running = self.busy_heavy()
            if running:
                raise RuntimeError(f"another test is running ({running.kind})")
        job = Job(kind)
        with self._lock:
            self._jobs[job.id] = job
            # keep memory bounded
            if len(self._jobs) > 50:
                for old in sorted(self._jobs.values(), key=lambda j: j.started)[:10]:
                    if old.state != "running":
                        self._jobs.pop(old.id, None)

        def runner():
            ctx = JobContext(job)
            try:
                job.result = fn(ctx)
                job.state = "done"
                job.progress = 1.0
            except Cancelled:
                job.state = "cancelled"
                log.info("job %s (%s) cancelled", job.id, kind)
            except Exception as e:     # never let a worker crash the app
                job.state = "error"
                job.error = f"{type(e).__name__}: {e}"
                log.error("job %s (%s) failed\n%s", job.id, kind, traceback.format_exc())
            finally:
                job.finished = time.time()

        threading.Thread(target=runner, name=f"job-{kind}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        j = self._jobs.get(job_id)
        if j and j.state == "running":
            j.cancel_event.set()
            return True
        return False
