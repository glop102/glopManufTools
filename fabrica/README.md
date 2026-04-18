# Fabrica

Architecture notes for the `fabrica` namespace.

## Namespace packages

`fabrica` is a Python implicit namespace package (PEP 420). There is intentionally no `fabrica/__init__.py` — only the individual module packages (e.g. `fabrica/discovery/__init__.py`) have init files.

This matters for Nix composition. `buildPythonApplication` wires dependencies together via `PYTHONPATH`, so each `fabrica.*` module lives in its own separate Nix store path:

```
/nix/store/xxx-fabrica-discovery/lib/pythonX/site-packages/fabrica/discovery/
/nix/store/yyy-fabrica-taskrunner/lib/pythonX/site-packages/fabrica/taskrunner/
```

Because neither `fabrica/` directory contains an `__init__.py`, Python merges them as a single namespace across all `PYTHONPATH` entries. Adding a new `fabrica.*` tool works without any changes to existing packages — just add its derivation to `overlay.nix` under `pythonPackagesExtensions` and list it as a dependency wherever it is needed.

If a `fabrica/__init__.py` were ever introduced (by listing `"fabrica"` in a `pyproject.toml` `packages` list), the first entry on `PYTHONPATH` would shadow all others and imports from the other store paths would break.
