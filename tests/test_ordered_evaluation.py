import asyncio
from contextvars import ContextVar
import threading
import pytest
import predicates
from instrlib.ordered_evaluation import OrderedEvaluation

@pytest.mark.asyncio
async def test_preparation_overlaps_but_submission_is_fifo():
    queue = OrderedEvaluation()
    both = asyncio.Event()
    started = []
    submitted = []
    async def run(i):
        async def prepare():
            started.append(i)
            if len(started) == 2: both.set()
            await asyncio.wait_for(both.wait(), 1)
            if i == 1: await asyncio.sleep(.02)
            return i
        async def submit(value): submitted.append(value)
        await queue.run(prepare, submit)
    await asyncio.gather(run(1), run(2))
    assert submitted == [1, 2]

@pytest.mark.asyncio
async def test_cancelled_caller_does_not_release_order_early():
    queue = OrderedEvaluation()
    release = asyncio.Event()
    started = asyncio.Event()
    order = []
    async def prepare(): started.set(); await release.wait()
    async def first_submit(_): order.append(1)
    first = asyncio.create_task(queue.run(prepare, first_submit))
    await started.wait()
    first.cancel()
    with pytest.raises(asyncio.CancelledError): await first
    async def ready(): return None
    async def second_submit(_): order.append(2)
    second = asyncio.create_task(queue.run(ready, second_submit))
    await asyncio.sleep(.01)
    assert order == []
    release.set()
    await second
    assert order == [1, 2]

@pytest.mark.asyncio
async def test_preparation_failure_does_not_overtake_previous():
    queue = OrderedEvaluation()
    release = asyncio.Event()
    order = []
    async def slow(): await release.wait()
    async def bad(): raise ValueError('failed')
    async def ready(): pass
    async def submit(_): order.append('submitted')
    tasks = [asyncio.create_task(queue.run(p, submit)) for p in (slow,bad,ready)]
    await asyncio.sleep(.01)
    assert order == []
    release.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert isinstance(results[1], ValueError)
    assert order == ['submitted','submitted']

def test_batched_groups_overlap_and_keep_request_context(monkeypatch):
    barrier = threading.Barrier(2)
    seen = []
    monkeypatch.setenv('ENFGUARD_PREDICATE_BATCH_WORKERS', '2')
    def judge(name, prompt, content, extra):
        barrier.wait(timeout=2)
        seen.append((content,predicates._current_sid(),predicates._current_tid()))
        return predicates.JudgeResult(raw_score=.25, reason="ok", reasons=())
    monkeypatch.setattr(predicates,'_judge',judge)
    tasks = [predicates.JudgeBatchTask('test','prompt',content,()) for content in ('a','b')]
    misses = [(i,t,str(i),('openai','model',1000)) for i,t in enumerate(tasks)]
    results = [None,None]
    with predicates.request_context(42,'session','tool'):
        predicates._dispatch_batched(misses,results)
    assert sorted(seen) == [('a','session',42),('b','session',42)]
    assert all(r.raw_score == .25 for r in results)

@pytest.mark.asyncio
async def test_request_context_isolated_across_concurrent_preparations():
    barrier = threading.Barrier(2)
    def inspect_request(tid, sid):
        with predicates.request_context(tid, sid, "tool"):
            barrier.wait(timeout=2)
            return predicates._current_context().copy()
    a, b = await asyncio.gather(
        asyncio.to_thread(inspect_request, 10, "one"),
        asyncio.to_thread(inspect_request, 20, "two"))
    assert (a["tid"], a["sid"]) == (10, "one")
    assert (b["tid"], b["sid"]) == (20, "two")
