import asyncio
import unittest


class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_empty_dag_never_invokes_worker(self):
        from gamedecomp.scheduler import run_jobs

        async def worker(job):
            self.fail("An empty DAG must not dispatch work")

        self.assertEqual(await run_jobs([], worker), {})

    async def test_worker_receives_payload_and_result_is_preserved(self):
        from gamedecomp.scheduler import Job, run_jobs

        payload = object()

        async def worker(job):
            self.assertIs(job.payload, payload)
            return payload

        result = await run_jobs([Job("one", frozenset(), payload)], worker)
        self.assertIs(result["one"], payload)

    async def test_worker_can_return_a_future(self):
        from gamedecomp.scheduler import Job, run_jobs

        def worker(job):
            future = asyncio.get_running_loop().create_future()
            future.set_result(job.payload)
            return future

        result = await run_jobs([Job("future", frozenset(), "result")], worker)
        self.assertEqual(result, {"future": "result"})

    async def test_worker_can_return_a_task_and_timeout_cleans_it_up(self):
        from gamedecomp.scheduler import Job, run_jobs

        started, cleaned, never = asyncio.Event(), asyncio.Event(), asyncio.Event()
        created = []
        before = asyncio.all_tasks()

        async def work():
            started.set()
            try:
                await never.wait()
            finally:
                cleaned.set()

        def worker(job):
            task = asyncio.create_task(work())
            created.append(task)
            return task

        try:
            with self.assertRaises(TimeoutError):
                await run_jobs([Job("task", frozenset())], worker, timeout=0.01)
            self.assertTrue(started.is_set())
            self.assertTrue(cleaned.is_set())
            self.assertEqual(asyncio.all_tasks(), before)
        finally:
            for task in created:
                task.cancel()
            await asyncio.gather(*created, return_exceptions=True)

    async def test_dependents_start_only_after_all_dependencies_complete(self):
        from gamedecomp.scheduler import Job, run_jobs

        release = asyncio.Event()
        roots_started = asyncio.Event()
        started, completed = set(), set()

        async def worker(job):
            started.add(job.id)
            if job.id in {"left", "right"}:
                if {"left", "right"} <= started:
                    roots_started.set()
                await release.wait()
            else:
                self.assertEqual(completed, {"left", "right"})
            completed.add(job.id)
            return job.id.upper()

        jobs = [
            Job("join", frozenset({"left", "right"})),
            Job("left", frozenset()),
            Job("right", frozenset()),
        ]
        task = asyncio.create_task(run_jobs(jobs, worker, workers=2))
        try:
            await asyncio.wait_for(roots_started.wait(), 1)
            self.assertNotIn("join", started)
            release.set()
            self.assertEqual(await task, {"left": "LEFT", "right": "RIGHT", "join": "JOIN"})
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_independent_jobs_run_in_parallel_with_worker_limit(self):
        from gamedecomp.scheduler import Job, run_jobs

        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                release = asyncio.Event()
                full = asyncio.Event()
                active = peak = started = 0

                async def worker(job):
                    nonlocal active, peak, started
                    active += 1
                    started += 1
                    peak = max(peak, active)
                    if active == workers:
                        full.set()
                    try:
                        await release.wait()
                        return job.id
                    finally:
                        active -= 1

                jobs = [Job(str(index), frozenset()) for index in range(9)]
                task = asyncio.create_task(run_jobs(jobs, worker, workers=workers))
                try:
                    await asyncio.wait_for(full.wait(), 1)
                    self.assertEqual(started, workers)
                    release.set()
                    self.assertEqual(len(await task), 9)
                    self.assertEqual(peak, workers)
                    self.assertEqual(active, 0)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)

    async def test_duplicate_missing_and_cyclic_jobs_are_rejected_before_dispatch(self):
        from gamedecomp.scheduler import Job, run_jobs

        cases = [
            ([Job("same", frozenset()), Job("same", frozenset())], "[Dd]uplicat"),
            ([Job("a", frozenset({"missing"}))], "[Dd]ipenden|[Dd]ependen"),
            ([Job("root", frozenset()), Job("a", frozenset({"b"})), Job("b", frozenset({"a"}))], "[Cc]icl|[Cc]ycl"),
            ([Job("self", frozenset({"self"}))], "[Cc]icl|[Cc]ycl"),
        ]

        async def worker(job):
            self.fail("Validation must finish before any dispatch")

        for jobs, message in cases:
            with self.subTest(jobs=jobs), self.assertRaisesRegex(ValueError, message):
                await run_jobs(jobs, worker)

    async def test_invalid_execution_limits_raise_value_error(self):
        from gamedecomp.scheduler import run_jobs

        async def worker(job):
            self.fail("Invalid limits must not dispatch work")

        cases = [{"workers": value} for value in (0, -1, 1.5, True, "2", None)]
        cases += [{"timeout": value} for value in (0, -1, float("nan"), float("inf"), True, "1", None)]
        for limits in cases:
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                await run_jobs([], worker, **limits)

    async def test_worker_failure_cancels_siblings_and_never_dispatches_dependents(self):
        from gamedecomp.scheduler import Job, run_jobs

        sibling_started = asyncio.Event()
        sibling_cleaned = asyncio.Event()
        never = asyncio.Event()
        before = asyncio.all_tasks()

        async def worker(job):
            if job.id == "fail":
                await sibling_started.wait()
                raise RuntimeError("worker failed")
            if job.id == "blocked":
                sibling_started.set()
                try:
                    await never.wait()
                finally:
                    sibling_cleaned.set()
            self.fail("A dependent must not start after worker failure")

        jobs = [
            Job("fail", frozenset()), Job("blocked", frozenset()),
            Job("dependent", frozenset({"fail"})),
        ]
        with self.assertRaisesRegex(RuntimeError, "worker failed"):
            await run_jobs(jobs, worker, workers=2)
        self.assertTrue(sibling_cleaned.is_set())
        self.assertEqual(asyncio.all_tasks(), before)

    async def test_timeout_waits_for_worker_cleanup_and_leaves_no_tasks(self):
        from gamedecomp.scheduler import Job, run_jobs

        cleaned = asyncio.Event()
        never = asyncio.Event()
        before = asyncio.all_tasks()

        async def worker(job):
            try:
                await never.wait()
            finally:
                await asyncio.sleep(0)
                cleaned.set()

        with self.assertRaises(TimeoutError):
            await run_jobs([Job("blocked", frozenset())], worker, timeout=0.01)
        self.assertTrue(cleaned.is_set())
        self.assertEqual(asyncio.all_tasks(), before)

    async def test_caller_cancellation_waits_for_worker_cleanup(self):
        from gamedecomp.scheduler import Job, run_jobs

        started, cleaned, never = asyncio.Event(), asyncio.Event(), asyncio.Event()
        before = asyncio.all_tasks()

        async def worker(job):
            started.set()
            try:
                await never.wait()
            finally:
                await asyncio.sleep(0)
                cleaned.set()

        task = asyncio.create_task(run_jobs([Job("blocked", frozenset())], worker))
        try:
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cleaned.is_set())
            self.assertEqual(asyncio.all_tasks(), before)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_repeated_caller_cancellation_does_not_interrupt_worker_cleanup(self):
        from gamedecomp.scheduler import Job, run_jobs

        started, cleanup_started, cleanup_release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        cleaned, never = asyncio.Event(), asyncio.Event()
        before = asyncio.all_tasks()

        async def worker(job):
            started.set()
            try:
                await never.wait()
            finally:
                cleanup_started.set()
                await cleanup_release.wait()
                cleaned.set()

        task = asyncio.create_task(run_jobs([Job("blocked", frozenset())], worker))
        try:
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            await asyncio.wait_for(cleanup_started.wait(), 1)
            task.cancel()
            cleanup_release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cleaned.is_set())
            self.assertEqual(asyncio.all_tasks(), before)
        finally:
            cleanup_release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_simultaneous_worker_failures_are_all_retrieved(self):
        from gamedecomp.scheduler import Job, run_jobs

        barrier = asyncio.Event()
        count = 0
        unhandled = []
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: unhandled.append(context))

        async def worker(job):
            nonlocal count
            count += 1
            if count == 2:
                barrier.set()
            await barrier.wait()
            raise RuntimeError(job.id)

        try:
            with self.assertRaises(RuntimeError):
                await run_jobs([Job("a", frozenset()), Job("b", frozenset())], worker, workers=2)
            await asyncio.sleep(0)
            self.assertEqual(unhandled, [])
        finally:
            loop.set_exception_handler(previous_handler)


class StronglyConnectedComponentsTests(unittest.TestCase):
    def test_groups_recursion_and_preserves_disconnected_and_target_only_nodes(self):
        from gamedecomp.scheduler import strongly_connected_components

        graph = {
            "a": ["b"], "b": ["c", "leaf"], "c": ["a"],
            "isolated": [], "self": ["self"], "other": ["target"],
        }
        result = strongly_connected_components(graph)
        self.assertEqual(
            {frozenset(group) for group in result},
            {frozenset({"a", "b", "c"}), frozenset({"leaf"}),
             frozenset({"isolated"}), frozenset({"self"}),
             frozenset({"other"}), frozenset({"target"})},
        )
        self.assertEqual(sum(map(len, result)), 8)

    def test_empty_graph_returns_no_components(self):
        from gamedecomp.scheduler import strongly_connected_components

        self.assertEqual(strongly_connected_components({}), [])

    def test_large_graph_does_not_depend_on_python_recursion_limit(self):
        from gamedecomp.scheduler import strongly_connected_components

        count = 5000
        graph = {str(index): [str(index + 1)] for index in range(count - 1)}
        graph[str(count - 1)] = ["0"]
        result = strongly_connected_components(graph)
        self.assertEqual(len(result), 1)
        self.assertEqual(set(result[0]), {str(index) for index in range(count)})

    def test_large_acyclic_graph_keeps_each_component_separate(self):
        from gamedecomp.scheduler import strongly_connected_components

        graph = {str(index): [str(index + 1)] for index in range(3000)}
        result = strongly_connected_components(graph)
        self.assertEqual(len(result), 3001)
        self.assertTrue(all(len(group) == 1 for group in result))
        self.assertEqual({group[0] for group in result}, {str(index) for index in range(3001)})
