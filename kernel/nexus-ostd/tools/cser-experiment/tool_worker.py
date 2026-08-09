"""Crash-recoverable worker for the trusted-local asynchronous endpoint."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from tool_provider import ProviderStore

if TYPE_CHECKING:
    from tool_endpoint import Store, WorkItem


class AsyncWorker:
    def __init__(self, store: "Store", provider: ProviderStore, *, worker_id: str,
                 lease_seconds: float = 2.0, poll_seconds: float = 0.01,
                 retry_backoff_min_seconds: float = 0.01, retry_backoff_max_seconds: float = 0.25) -> None:
        if retry_backoff_min_seconds <= 0 or retry_backoff_max_seconds < retry_backoff_min_seconds:
            raise ValueError("invalid worker retry backoff")
        self.store, self.provider = store, provider
        self.worker_id, self.lease_seconds, self.poll_seconds = worker_id, lease_seconds, poll_seconds
        self.retry_backoff_min_seconds = retry_backoff_min_seconds
        self.retry_backoff_max_seconds = retry_backoff_max_seconds
        self._failure_streak = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> bool:
        item = self.store.claim_next(self.worker_id, self.lease_seconds)
        if item is None:
            return False
        identity = (item.namespace_id, item.authority_id, item.effect_id, item.catalog_digest,
                    item.run_id, item.operation_key)
        try:
            # Query first on every lease.  In particular, this repairs the
            # provider-apply-before-adapter-terminal crash window without a
            # duplicate external apply.
            outcome = self.provider.query(identity, item.input_digest)
            if outcome is None:
                outcome = self.provider.apply(identity, item.input_digest, item.payload)
            self.store.complete_lease(item, outcome.state, outcome.result)
            self._failure_streak = 0
        except (OSError, sqlite3.Error):
            # Infrastructure failure is deliberately nonterminal.  A later
            # lease will query the provider again before attempting dispatch.
            self.store.release_lease(item)
            self.store.record_infrastructure_retry()
            delay = min(self.retry_backoff_min_seconds * (2 ** self._failure_streak), self.retry_backoff_max_seconds)
            self._failure_streak = min(self._failure_streak + 1, 30)
            self.store.record_infrastructure_backoff()
            self._stop.wait(delay)
        return True

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name=f"cser-worker-{self.worker_id}", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            if not self.run_once():
                self._stop.wait(self.poll_seconds)

    def stop(self) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            return not self._thread.is_alive()
        return True


# Avoid a runtime import cycle while retaining an explicit narrow error set.
import sqlite3  # noqa: E402
