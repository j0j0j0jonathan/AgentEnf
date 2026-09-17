# Third-party notices

AgentEnf is distributed under GPL-3.0. Original AgentEnf contributions are by Jonathan Hofer. Copyright and license notices for inherited components remain applicable.

## InstrLib

The instrumentation layer builds on [InstrLib](https://github.com/runtime-enforcement/instrlib), associated with *Instrumenting Runtime Enforcement* by F. Hublet, D. Basin, L. Hu, S. Krstić and L. Reese. `instrlib/handler_graph.py` identifies itself as copied from InstrLib, and `instrlib/event.py` identifies its adaptation from the miniTwitter case study. The integration has subsequently been adapted for AgentEnf.

InstrLib is licensed under GPL-3.0. Its license text is included in `licenses/InstrLib-LICENSE`. Existing source attribution is retained.

## EnfGuard / WhyEnf

The separately installed [EnfGuard/WhyEnf monitor](https://github.com/runtime-enforcement/whyenf) is developed by François Hublet, Leonardo Lima, Srđan Krstić, Dmitriy Traytel and David Basin. Its upstream project uses LGPL-3.0. No monitor executable or upstream source checkout is bundled in this repository.

## Other dependencies

Python and frontend dependencies are installed through their package managers and retain their own licenses. OpenClaw, NanoClaw, and ASEval/A3S-Bench are external projects. This repository contains integration code and links to their sources, not redistributed copies of those projects or benchmark datasets.
