# EnfGuard monitor

AgentEnf launches the separately installed OCaml [EnfGuard/WhyEnf monitor](https://github.com/runtime-enforcement/whyenf). The integration expects its `new_temp` interface, including labelled MFOTL formula composition and JSON enforcement output. A generic MonPoly binary is not a substitute.

Follow the upstream build instructions. The development toolchain used OCaml 4.13.1 and opam. A typical source installation is:

```bash
git clone --branch new_temp https://github.com/runtime-enforcement/whyenf.git
cd whyenf
opam switch create . 4.13.1
eval "$(opam env)"
opam install dune core_kernel core_unix base zarith menhir \
  zarith_stubs_js dune-build-info qcheck pyml calendar str z3 yojson cmdliner
dune build
export ENFGUARD_BIN="$PWD/_build/default/bin/enfguard.exe"
```

PyML must be able to load a compatible Python shared library. If your build requires a particular interpreter prefix, set `ENFGUARD_PYTHONHOME` to that prefix. `ENFGUARD_DYLD_LIBRARY_PATH` optionally sets the monitor's dynamic-library search directory on macOS or Linux. AgentEnf no longer auto-selects a developer's Conda installation.

Set `ENFGUARD_TIME_MODE=wall_seconds` so metric intervals use seconds. The `tid` event argument remains an identity, separate from the trace timestamp. `logical` is available for older monitors and test fixtures.

Run `ENFGUARD_BIN=/absolute/path/to/enfguard.exe python -m pytest` to exercise the monitor integration tests. The monitor is a separate upstream project and retains its own license.
