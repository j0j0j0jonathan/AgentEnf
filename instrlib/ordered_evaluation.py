"""Overlap evidence preparation while preserving monitor submission order."""
import asyncio


class OrderedEvaluation:
    def __init__(self):
        self.tail = None

    async def wait_previous(self, previous):
        if previous is not None:
            await asyncio.shield(previous)

    async def run(self, prepare, submit):
        previous = self.tail
        done = asyncio.get_running_loop().create_future()
        self.tail = done

        async def execute():
            try:
                prepared = await prepare()
                await self.wait_previous(previous)
                return await submit(prepared)
            finally:
                # A failed preparation must not let its successor pass a still
                # running earlier submission. Caller cancellation also leaves
                # this owner task alive until ordering and locks are resolved.
                await self.wait_previous(previous)
                done.set_result(None)
                if self.tail is done:
                    self.tail = None

        task = asyncio.create_task(execute())
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Retrieve failures even when the HTTP caller has disconnected.
            task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
            raise
