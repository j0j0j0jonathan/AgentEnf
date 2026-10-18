"""Real-engine exact-text checks; deliberately do not emulate EnfGuard garbling."""

import json
import os
from pathlib import Path
import pytest
from instrlib import Event
from instrlib.enfflash import EnfFlashEnforcer

ROOT = Path(__file__).resolve().parents[1]


def binaries():
    compiler = Path(os.environ.get("ENFFLASH_COMPILER", ""))
    runtime = Path(os.environ.get("ENFFLASH_BIN", ""))
    if not compiler.is_file() or not runtime.is_file():
        pytest.skip("Set EnfFlash binaries for real engine")
    return compiler, runtime


def engine(tmp_path, signature, formula, functions=None, env=None):
    compiler, runtime = binaries()
    sig = tmp_path / "test.sig"
    sig.write_text(signature)
    policy = tmp_path / "test.mfotl"
    policy.write_text(formula)
    fun = None
    if functions:
        fun = tmp_path / "test_predicates.py"
        fun.write_text(functions)
    return EnfFlashEnforcer(
        str(runtime),
        str(sig),
        str(policy),
        compiler=compiler,
        cache_dir=tmp_path / "compiled",
        fun=str(fun) if fun else None,
        env={**os.environ, **(env or {})},
    )


def test_exact_strings_reach_actual_pre_evaluated_lookup(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    names = [
        "reveals_secret_value",
        "reveals_private_control_instructions",
        "operationalizes_untrusted_harm",
        "requests_exact_secret_disclosure",
    ]
    (state / "active_policies.json").write_text(
        json.dumps(
            {
                "active": ["p"],
                "predicate_policies": {n: ["p"] for n in names},
                "user_predicates": [
                    {
                        "name": n,
                        "kind": "llm_judge",
                        "system_prompt": "offline fixture",
                        "args": [{"name": "content", "type": "string"}],
                    }
                    for n in names
                ],
            }
        )
    )
    received = tmp_path / "calls.jsonl"
    functions = ""
    for name in names:
        functions += f"""def {name}(content):
    import json, os
    from pathlib import Path
    import predicates as actual
    def no_api(*args, **kwargs):
        raise AssertionError('Unexpected API call: exact evidence was lost')
    actual._call_and_parse_judge_api=no_api
    evidence=actual._pre_evaluated_judge_result({name!r},content)
    if evidence is None: raise AssertionError('No exact recorded evidence')
    value=getattr(actual,{name!r})(content)
    with open({str(received)!r},'a') as f: f.write(json.dumps([{name!r},content,value])+"\\n")
    return value
"""
    signature = "Input(t:int,content:string)\nDeny(t:int,label:string)+\n" + "\n".join(
        f"fun {n}(content:string) : float" for n in names
    )
    formula = " AND ".join(
        f'ALWAYS (FORALL t,content. (Input(t,content) AND {n}(content)>0.5) IMPLIES:R Deny(t,"{n}"))'
        for n in names
    )
    env = {
        "ENFGUARD_STATE_DIR": str(state),
        "ENFGUARD_LOG_DIR": str(tmp_path / "logs"),
        "ENFGUARD_CONTEXT_FILE": str(state / "current_context.json"),
        "ENFGUARD_SESSIONS_DIR": str(state / "sessions"),
        "PYTHONPATH": os.pathsep.join(
            [str(ROOT), str(ROOT / ".venv/lib/python3.12/site-packages")]
        ),
    }
    enf = engine(tmp_path, signature, formula, functions, env)
    values = [
        "plain ASCII",
        'quoted "word"',
        r"path\with\backslashes",
        "line one\nline two",
        "curly “quoted”",
        "Grüße 秘密",
        "tab\tvalue",
        r"literal \n escape",
        "user www-data;\nworker_processes 2;\n",
        "first;\r\nsecond;\r\n",
        'literal "quote" and \\;\n> measurement-looking data <\nGrüße 秘密',
    ]
    try:
        enf.start()
        for t, text in enumerate(values, 1):
            context = {"tid": t, "sid": f"s{t}", "phase": "outbound", "dry_run": 0}
            (state / "current_context.json").write_text(json.dumps(context))
            (state / "pre_eval_results.jsonl").write_text(
                "".join(
                    json.dumps(
                        {
                            **context,
                            "predicate": n,
                            "content": text,
                            "raw_score": float(t % 2),
                            "reason": "exact",
                        }
                    )
                    + "\n"
                    for n in names
                )
            )
            result = enf.query([Event("Input", t, text)], t)
            got = {x["args"][1] for x in result.get("cause", []) if x["name"] == "Deny"}
            assert got == (set(names) if t % 2 else set())
    finally:
        enf.stop()
    calls = [json.loads(x) for x in received.read_text().splitlines()]
    # An engine may evaluate a predicate more than once when enforcing/checking.
    assert {(c[0], c[1]) for c in calls} == {(n, v) for n in names for v in values}
    journal = tmp_path / "logs/predicate_evidence"
    captured = [
        json.loads(line)
        for p in journal.glob("calls-*.jsonl")
        for line in p.read_text().splitlines()
    ]
    assert captured and all(r["origin"] == "exact_pre_evaluation" for r in captured)
    assert {(journal / r["input"]["file"]).read_bytes().decode('utf-8') for r in captured} == set(values)


def test_dynamic_verdict_strings_are_valid_json(tmp_path):
    monitor = engine(tmp_path,
        'Input(t:int,content:string)\nBlock(t:int,phase:string,category:string,reason:string)+\n',
        'ALWAYS (FORALL t,content. Input(t,content) IMPLIES:R Block(t,"probe","roundtrip",content))')
    values = ['first;\nsecond;', 'CRLF;\r\nnext', '"quoted" \\ slash\ttab\x00NUL', 'Grüße 秘密']
    try:
        monitor.start()
        for tid, value in enumerate(values, 1):
            result = monitor.query([Event('Input', tid, value)], tid)
            assert [e['args'][3] for e in result.get('cause', []) if e['name'] == 'Block'] == [value]
    finally:
        monitor.stop()


@pytest.mark.parametrize("pack", ["release-candidate", "optimized-v1"])
def test_full_candidate_compiles_and_uses_confirmed_state_only(tmp_path, pack):
    import yaml
    from dataclasses import replace
    from config import CONFIG
    from yaml_loader import load

    compiler, runtime = binaries()
    config = replace(
        CONFIG,
        state_dir=tmp_path / "state",
        logs_dir=tmp_path / "logs",
        monitor_backend="enfflash",
        enfflash_compiler=compiler,
        enfflash_bin=runtime,
        yaml_file=ROOT / f"examples/presets/{pack}.yaml",
        composite_signature_file=tmp_path / "combined.sig",
        composite_policy_file=tmp_path / "combined.mfotl",
    )
    loaded = load(config.yaml_file, config)
    # No predicate calls in these synthetic artifact events. Importing the real
    # predicate module is lazy, just as in the proxy backend.
    enf = EnfFlashEnforcer(
        str(runtime),
        str(config.composite_signature_file),
        str(loaded.merged_mfotl_path),
        compiler=compiler,
        cache_dir=tmp_path / "cache",
        fun=str(ROOT / "predicates.py"),
    )
    try:
        enf.start()
        for t, dim, expected in [
            (1, "artifact_attempted_dangerous_path_v3", "Approve"),
            (2, "artifact_present_dangerous_path_v3", "Block"),
            (3, "artifact_state_unresolved", "Approve"),
            (4, "authored_history_risk", "Approve"),
        ]:
            result = enf.query(
                [
                    Event("PolicyActive", t, "artifact_provenance_v3"),
                    Event("ToolPlanned", t, str(t), "bash", "{}"),
                    Event("Classify", t, str(t), dim, "fixture"),
                ],
                t,
            )
            assert {e["name"] for e in result.get("cause", [])} == {expected}
    finally:
        enf.stop()


def test_embedded_python_sees_launching_venv_dependencies(tmp_path, monkeypatch):
    import sysconfig
    # Match the pilot: module paths are explicit but site-packages was absent.
    monkeypatch.setenv('PYTHONPATH', str(ROOT))
    functions = '''def available(t):
    import markdown_it
    from instrlib.reply_guard import STRATEGY
    assert markdown_it.__version__ == "4.2.0"
    assert STRATEGY == "reply_guard_v1"
    return 1.0
'''
    signature = 'Input(t:int)\nOk(t:int)+\nfun available(t:int) : float\n'
    formula = 'ALWAYS (FORALL t. (Input(t) AND available(t)>0.5) IMPLIES:R Ok(t))'
    monitor = engine(tmp_path, signature, formula, functions)
    paths = monitor._env['PYTHONPATH'].split(os.pathsep)
    assert paths[0] == str(ROOT)
    assert sysconfig.get_paths()['purelib'] in paths
    try:
        monitor.start()
        result = monitor.query([Event('Input', 1)], 1)
        assert any(e['name'] == 'Ok' for e in result.get('cause', []))
    finally:
        monitor.stop()


def test_native_background_launch_requests_approval(tmp_path):
    import yaml
    from instrlib.tool_mapper import map_tool_call
    from experiments.release_candidate.build_optimized import clauses
    pack = yaml.safe_load((ROOT / 'examples/presets/release-candidate.yaml').read_text())
    group = next(p for p in pack['policies'] if p['id'] == 'execution_v2')
    clause = dict(clauses(group['mfotl']))['background_daemon']
    compiler, runtime = binaries()
    formula = tmp_path / 'background.mfotl'
    formula.write_text(clause)
    monitor = EnfFlashEnforcer(str(runtime), str(ROOT / 'enfguard.sig'), str(formula),
                              compiler=compiler, cache_dir=tmp_path / 'cache')
    monitor.start()
    try:
        events = map_tool_call(1, 'c', 'bash', {'command': 'sleep 30', 'background': True})
        call = next(e for e in events if e.name == 'ToolCall')
        result = monitor.query([Event('PolicyActive', 1, 'execution_v2'),
                                Event('ToolPlanned', *call.args), *events], 1)
        assert any(e['name'] == 'Approve' and e['args'][2] == 'background_daemon'
                   for e in result.get('cause', []))
    finally:
        monitor.stop()
