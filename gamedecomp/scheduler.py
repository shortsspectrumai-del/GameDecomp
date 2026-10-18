"""Bounded asynchronous scheduling of validated dependency graphs.

Workers own external processes and must cooperate with asyncio cancellation.
The scheduler waits for every worker it started before returning or raising.
"""

from __future__ import annotations

import asyncio
import math
from collections import deque
from collections.abc import Awaitable, Callable, Iterable, Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Job:
    id: str
    dependencies: frozenset[str]
    payload: object = None


async def run_jobs(
    jobs: Iterable[Job],
    worker: Callable[[Job], Awaitable[object]],
    *,
    workers: int = 4,
    timeout: float = 300,
) -> dict[str, object]:
    """Run a DAG, dispatching each job after its dependencies succeed.

    Invalid limits, duplicate IDs, missing dependencies and cycles raise
    ``ValueError`` before a worker starts. Worker errors propagate unchanged.
    The deadline covers the whole execution and raises ``TimeoutError``;
    failure, timeout and caller cancellation cancel and await active workers.
    """
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a finite positive number")

    by_id: dict[str, Job] = {}
    for job in jobs:
        if job.id in by_id:
            raise ValueError(f"Duplicate job ID: {job.id!r}")
        by_id[job.id] = job

    children: dict[str, list[str]] = {key: [] for key in by_id}
    pending = {key: len(job.dependencies) for key, job in by_id.items()}
    for job in by_id.values():
        for dependency in sorted(job.dependencies):
            if dependency not in by_id:
                raise ValueError(f"Dependency {dependency!r} of job {job.id!r} does not exist")
            children[dependency].append(job.id)

    ready = deque(key for key, count in pending.items() if count == 0)
    probe, counts, visited = deque(ready), pending.copy(), 0
    while probe:
        key = probe.popleft()
        visited += 1
        for child in children[key]:
            counts[child] -= 1
            if counts[child] == 0:
                probe.append(child)
    if visited != len(by_id):
        raise ValueError("Cycle in job dependencies; group strongly connected components first")

    async def execute(job: Job) -> object:
        # Own a task for every job, even when the callback returns a Future
        # or an already-started Task rather than a coroutine object.
        return await worker(job)

    running: dict[asyncio.Task[object], str] = {}
    completed: dict[str, object] = {}
    try:
        async with asyncio.timeout(timeout):
            while ready or running:
                while ready and len(running) < workers:
                    key = ready.popleft()
                    task = asyncio.create_task(execute(by_id[key]), name=f"gamedecomp:{key}")
                    running[task] = key
                finished, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
                # Check the entire batch before publishing successes: a failure
                # must not release more dependent work from this same batch.
                batch = [
                    (task, running[task], task.result())
                    for task in sorted(finished, key=lambda task: running[task])
                ]
                for task, key, result in batch:
                    del running[task]
                    completed[key] = result
                    for child in children[key]:
                        pending[child] -= 1
                        if pending[child] == 0:
                            ready.append(child)
    finally:
        for task in running:
            task.cancel()
        cleanup = asyncio.gather(*running, return_exceptions=True)
        interrupted: asyncio.CancelledError | None = None
        while True:
            try:
                # A second cancellation must not reach a worker already
                # awaiting resource release in its own finally block.
                await asyncio.shield(cleanup)
                break
            except asyncio.CancelledError as error:
                interrupted = error
        if interrupted is not None:
            raise interrupted
    return completed


def strongly_connected_components(graph: dict[str, list[str]]) -> list[list[str]]:
    """Partition all nodes, including targets absent from graph keys.

    Iterative Kosaraju traversal uses O(V + E) time and storage without
    consuming Python's call stack. Input insertion order determines traversal
    order; callers should treat component membership as the graph contract.
    The input graph is not modified.
    """
    adjacency = {node: list(targets) for node, targets in graph.items()}
    for targets in graph.values():
        for target in targets:
            adjacency.setdefault(target, [])

    reverse: dict[str, list[str]] = {node: [] for node in adjacency}
    for node, targets in adjacency.items():
        for target in targets:
            reverse[target].append(node)

    visited: set[str] = set()
    finish_order: list[str] = []
    for root in adjacency:
        if root in visited:
            continue
        visited.add(root)
        stack: list[tuple[str, Iterator[str]]] = [(root, iter(adjacency[root]))]
        while stack:
            node, targets = stack[-1]
            target = next(targets, None)
            if target is None:
                stack.pop()
                finish_order.append(node)
            elif target not in visited:
                visited.add(target)
                stack.append((target, iter(adjacency[target])))

    components: list[list[str]] = []
    visited.clear()
    for root in reversed(finish_order):
        if root in visited:
            continue
        visited.add(root)
        component: list[str] = []
        queue = [root]
        while queue:
            node = queue.pop()
            component.append(node)
            for predecessor in reverse[node]:
                if predecessor not in visited:
                    visited.add(predecessor)
                    queue.append(predecessor)
        components.append(component)
    return components
