"""Opt-in EnfFlash backend with exact Python strings and isolated compilation.

No fallback to the old engine on failure. Original policies are preserved along
with the compilation transform and binary hashes. This is a candidate backend;
historical garbled-input behavior is deliberately not emulated.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sysconfig
import tempfile

from instrlib.enforcer import Enforcer
from instrlib.flash_formula import rewrite, without_labels


class EnfFlashEnforcer(Enforcer):
    def __init__(self, *args, compiler, cache_dir, **kwargs):
        env = dict(kwargs.get("env") or os.environ)
        env.setdefault("ENFGUARD_CAPTURE_PREDICATE_INPUTS", "1")
        env["ENFGUARD_MONITOR_PREDICATE_DIAGNOSTICS"] = "1"
        # Rust embeds CPython rather than launching this venv's executable.
        # Share the launching runtime's installed dependencies with predicate
        # imports; otherwise a pre-evaluation cache lookup can fail importing
        # e.g. markdown_it before it ever reaches the cached answer.
        paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
        installed = sysconfig.get_paths()
        for kind in ("purelib", "platlib"):
            path = installed.get(kind)
            if path and path not in paths:
                paths.append(path)
        env["PYTHONPATH"] = os.pathsep.join(paths)
        kwargs["env"] = env
        super().__init__(*args, **kwargs)
        self.compiler = Path(compiler)
        self.cache_dir = Path(cache_dir)

    @staticmethod
    def _format(events, timestamp):
        return Enforcer._format(events, timestamp) + b"\n"

    def _command(self):
        source = Path(self._formula).read_text()
        transformed, changes = rewrite(source)
        transformed, labels = without_labels(transformed)
        signature = Path(self._sig).read_text()
        wrappers = ""
        if self._fun:
            function_file = Path(self._fun).resolve()
            # The compiler extracts function bodies. Import the actual module
            # lazily inside the Rust process, never in the compiler's Python.
            for name, args in re.findall(r"^fun\s+(\w+)\(([^)]*)\)", signature, re.M):
                names = [a.split(":")[0].strip() for a in args.split(",") if a.strip()]
                if not all(re.fullmatch(r"[A-Za-z_]\w*", n) for n in [name, *names]):
                    raise ValueError("Invalid predicate name or argument in signature")
                wrappers += (
                    f"def {name}({', '.join(names)}):\n"
                    "    import importlib\n    import sys\n"
                    f"    sys.path.insert(0, {str(function_file.parent)!r})\n"
                    f"    return getattr(importlib.import_module({function_file.stem!r}), {name!r})({', '.join(names)})\n"
                )
        hashes = {
            str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [self.compiler, Path(self._binary), Path(self._sig), Path(self._formula)]
        }
        if self._fun:
            hashes[self._fun] = hashlib.sha256(Path(self._fun).read_bytes()).hexdigest()
        digest = hashlib.sha256(
            json.dumps([hashes, transformed, wrappers], sort_keys=True).encode()
        ).hexdigest()
        directory = self.cache_dir / digest
        directory.mkdir(parents=True, exist_ok=True)
        formula = directory / "policy.mfotl"
        functions = directory / "functions.py"
        formula.write_text(transformed)
        functions.write_text(wrappers)
        program = directory / "program.ef"
        if not program.exists():
            fd, temporary = tempfile.mkstemp(dir=directory, suffix=".ef")
            os.close(fd)
            command = [
                str(self.compiler),
                "-sig",
                self._sig,
                "-formula",
                str(formula),
                "-no-run",
                "-output",
                temporary,
            ]
            if wrappers:
                command += ["-func", str(functions)]
            try:
                result = subprocess.run(command, capture_output=True, timeout=60, env=self._env)
                (directory / "compile.log").write_bytes(result.stdout + result.stderr)
                if result.returncode:
                    raise RuntimeError(
                        f"EnfFlash compilation failed; see {directory / 'compile.log'}"
                    )
                os.replace(temporary, program)
            finally:
                Path(temporary).unlink(missing_ok=True)
        (directory / "manifest.json").write_text(
            json.dumps(
                {
                    "source_hashes": hashes,
                    "scoped_rewrites": changes,
                    "removed_label_metadata": labels,
                    "original_formula": self._formula,
                    "exact_strings_required": True,
                },
                indent=2,
            )
            + "\n"
        )
        return [self._binary, "--program", str(program), "--json"]
