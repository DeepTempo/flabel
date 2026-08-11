# flabel

Label malicious flows in unlabeled packet captures.

`flabel` takes a packet capture file and produces Zeek logs plus a companion `labels.json`
describing the malicious flows found inside it. The intended consumer is model training: the
output is meant to serve as ground truth for detection models, so **label trustworthiness —
and recording how each verdict was reached — matters more than label volume.**

Detections come from two complementary paths:

- **Content inspection** — the capture is replayed past inline inspection (IPS/IDS) and the
  resulting detections are queried back, bounded by the replay window.
- **Encrypted traffic** — MITM is impossible on an after-the-fact capture, so TLS fingerprints
  (JA3/JA4) computed by Zeek are matched against a collated list of high-trust feeds.

Both sets are consolidated into one master list, and every entry records its detection source.

## Status

**Pre-research.** No working code yet. This repo currently holds the design brief and scaffolding.

This project follows a 7-stage pipeline — research → PRD → eng review → plan → scaffold →
build → verify — tracked in [`docs/status.yaml`](docs/status.yaml), with one GitHub issue per
stage. The original design brief is [`docs/prep-n-research.md`](docs/prep-n-research.md).

## Output layout

```
{input-pcap-name}/
├── zeek/          # all Zeek logs from processing the capture
└── labels.json    # malicious-flow verdicts
```

Exact `labels.json` schema is deliberately unsettled — it is a PRD-stage decision.

## Develop

Requires [uv](https://docs.astral.sh/uv/). Python 3.12 is provisioned automatically.

```sh
uv sync                # install
uv run pytest -q       # test
uv run ruff check .    # lint
uv run flabel --help   # run
```

## License

TBD — to be set before first release.
