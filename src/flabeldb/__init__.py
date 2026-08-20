"""The label store: a derived index over the archive of published runs.

Separate from `flabel` on purpose. `flabel` declares `dependencies = []` and
`tests/test_architecture.py` keeps a closed list of network-capable modules; a BigQuery client is
both a dependency and network I/O. That is the same argument that put the GCS upload in
`tools/flabel-run` rather than in Python (#134), one layer out — including its sharper half, that
shelling out to `gcloud` from inside `flabel` would *sidestep* the guard rather than satisfy it.

Nothing here may be imported from `flabel`, and a test enforces it in both directions.

Contracts: `docs/spec-label-store.md`. The four BigQuery behaviours that were measured rather than
assumed — a failed load job burning its job id, a struct field being unpartitionable, the job-id
namespace including the location, and the bucket's region — are §10 of that document.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.0.0"
