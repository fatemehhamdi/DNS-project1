# Contributors

Fill in the real contribution of each group member before submission. The
tool is organised so each person can own one part end-to-end (design,
implementation, tests, and individual defense).

| Member (name / student id) | Owned modules | Design + test + defense notes |
|---|---|---|
|  | `builder.py`, `runner.py` | dual-mode build; sandboxed execution & resource limits |
|  | `crash.py`, `classify.py` | crash evidence extraction; security/functional classification |
|  | `diffparse.py`, `correlate.py`, `hardening.py` | patch-to-finding correlation; ELF hardening |
|  | `minimize.py`, `regression.py`, `cli.py`, `report.py` | minimization, reproducers, CI integration |

Shared: target programs (`targets/`), test suites, documentation.
