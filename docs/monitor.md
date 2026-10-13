# Install the EnfGuard monitor

AgentEnf is the Python proxy and instrumentation layer. It starts a separate OCaml
[EnfGuard/WhyEnf monitor](https://github.com/runtime-enforcement/whyenf) to evaluate
and enforce the temporal formulas. You need both. AgentEnf does not bundle that
binary, and a generic MonPoly executable is not a substitute.

## Build from source

Use macOS or Linux with Git, a C/C++ toolchain, [opam](https://opam.ocaml.org/doc/Install.html)
and the native libraries required by its packages (for example GMP development
headers). On macOS, install the Command Line Tools if no compiler is available;
on Linux use your distribution's compiler/development packages.

The integration targets the monitor's `new_temp` interface, including labelled
MFOTL composition and JSON enforcement output. A source build following the
upstream development setup is:

```bash
git clone --branch new_temp https://github.com/runtime-enforcement/whyenf.git
cd whyenf
opam init --bare
opam switch create . 4.13.1
eval "$(opam env)"
opam install dune core_kernel core_unix base zarith menhir \
  zarith_stubs_js dune-build-info qcheck pyml calendar str z3 yojson cmdliner
dune build
```

Run `opam init` only if opam is not already initialized. Accept/install missing
native dependencies reported by opam. Monitor dependencies and branch contents
can change: consult its README and opam metadata if dependency solving fails.
This is a build recipe, not a pinned dependency lockfile.

The expected output is `_build/default/bin/enfguard.exe` inside the monitor
checkout. Check it exists and is executable:

```bash
test -x "$PWD/_build/default/bin/enfguard.exe"
```

A successful command exits with status zero and no output. Copy the absolute
path for the AgentEnf quickstart's `init --monitor` argument. Then return to the
AgentEnf checkout and activate its Python venv.

## Python / PyML compatibility

The monitor embeds Python through PyML to call policy predicates. The Python
interpreter/shared library it loads must be compatible with its build and must
be able to import AgentEnf's dependencies. AgentEnf requires Python 3.12+.
Activating a Python venv does not necessarily change which shared library a
previously built PyML selects.

Inspect the interpreter you intend to use:

```bash
python -c 'import sys, sysconfig; print(sys.version); print(sys.base_prefix); print(sysconfig.get_config_var("LIBDIR")); print(sysconfig.get_config_var("LDLIBRARY"))'
python -c 'import httpx, yaml; print("Python dependencies available")'
```

If needed, set these **in the terminal starting AgentEnf**, using values from the
compatible Python installation (not paths copied from someone else's machine):

```bash
export ENFGUARD_PYTHONHOME=/absolute/path/to/compatible/python-prefix
export ENFGUARD_DYLD_LIBRARY_PATH=/absolute/path/to/compatible/python-library-directory
```

Use the base Python prefix, not the `.venv` directory, for `ENFGUARD_PYTHONHOME`.
AgentEnf applies these to the monitor subprocess. The second setting becomes
`DYLD_LIBRARY_PATH` on macOS or `LD_LIBRARY_PATH` on Linux. Do not globally set
`PYTHONHOME` in your shell to try random prefixes; mismatches can break Python
startup. A source-built Python may need shared-library support enabled.

| Error or symptom | What to check |
|---|---|
| `opam` / `dune` not found | Install opam, activate its switch with `eval "$(opam env)"`, install dependencies. |
| Monitor executable missing | Wait for `dune build` to succeed and use its absolute output path. |
| Unknown flags, formula syntax or JSON-protocol errors | Verify the compatible monitor branch/interface; not every monitor binary is interchangeable. |
| `libpython` / shared-library loading error | Check Python version, shared-library availability, architecture (ARM versus x86) and the settings above. |
| Embedded Python cannot import modules | Check the monitor's selected Python installation and its access to the installed AgentEnf dependencies. |
| Proxy starts but `/health` reports `ok: false` | Inspect the proxy terminal for monitor startup/termination details. A running HTTP server alone is insufficient. |

The [quickstart](quickstart.md) checks actual decisions rather than only checking
the executable's presence. It does not exercise an external semantic API.
To include monitor integration tests, from AgentEnf's activated venv run:

```bash
ENFGUARD_BIN=/absolute/path/to/enfguard.exe python -m pytest
```

Without that explicit variable, monitor-dependent tests may skip. Use
`ENFGUARD_TIME_MODE=wall_seconds` for temporal windows expressed in seconds;
`tid` remains an event identity, not elapsed time. The helper sets this for you.
The monitor is a separate upstream project and retains its own license.
