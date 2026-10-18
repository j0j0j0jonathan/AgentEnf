import json
from threading import BoundedSemaphore
import pytest
import predicates
from instrlib import predicate_progress


def test_saturated_model_slots_fail_instead_of_hanging(monkeypatch):
    slots = BoundedSemaphore(1)
    slots.acquire()
    monkeypatch.setattr(predicates, '_MODEL_SLOTS', slots)
    with pytest.raises(TimeoutError, match='predicate_model_slot_timeout'):
        with predicates._model_slot(.001):
            pytest.fail('entered without a slot')
    slots.release()
    with predicates._model_slot(.001):
        pass


def test_contended_file_lock_has_deadline(monkeypatch):
    class Handle:
        def fileno(self): return 123
    def blocked(*args): raise BlockingIOError()
    monkeypatch.setattr(predicates.fcntl, 'flock', blocked)
    clock = iter([0, 6])
    monkeypatch.setattr(predicates.time, 'monotonic', lambda: next(clock))
    with pytest.raises(TimeoutError, match='predicate_cache_file_lock_timeout'):
        predicates._lock_cache_file(Handle())


def test_progress_records_identity_without_content(monkeypatch, tmp_path):
    monkeypatch.setenv('ENFGUARD_MONITOR_PREDICATE_DIAGNOSTICS', '1')
    timers = []
    monkeypatch.setattr(predicate_progress.faulthandler, 'dump_traceback_later', lambda *a, **k: timers.append('start'))
    monkeypatch.setattr(predicate_progress.faulthandler, 'cancel_dump_traceback_later', lambda: timers.append('cancel'))
    with predicate_progress.tracking(tmp_path, 'judge', 'private sample'):
        predicate_progress.stage('classifier_call')
    text = next(tmp_path.rglob('progress-*.jsonl')).read_text()
    assert 'private sample' not in text
    assert [json.loads(line)['stage'] for line in text.splitlines()] == ['entered', 'classifier_call', 'returned']
    assert timers == ['start', 'cancel']


def test_cache_timeout_preserves_failure_contract(monkeypatch):
    def timeout(*a, **k): raise TimeoutError('predicate_cache_file_lock_timeout')
    monkeypatch.setattr(predicates, '_judge_impl', timeout)
    monkeypatch.setenv('ENFGUARD_CAPTURE_PREDICATE_INPUTS', '0')
    monkeypatch.setattr(predicates, '_failed_judge_result', lambda name, exc: (name, str(exc)))
    assert predicates._judge('judge', 'criterion', 'text') == ('judge', 'predicate_cache_file_lock_timeout')
