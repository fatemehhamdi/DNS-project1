"""patchval - Security Patch Validation and Regression Testing for CI/CD.

A dynamic analysis harness that compiles a vulnerable "base" and a "patched"
version of a C/C++ target, runs a documented test suite against both in
release and sanitized builds, and answers two questions with concrete,
reproducible evidence:

  1. Does the previously-observed security error still occur in the patched
     version within the defined test scope?
  2. Did the patch preserve the program's expected behaviour on valid input?

The tool never trusts the patched binary's own output as ground truth: the
correctness oracle is an independent reference defined per test case.
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
