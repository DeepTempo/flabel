# The benign corpus

Seventeen captures of ordinary protocol traffic, used as the **broad** false-positive review.
`../benign.pcap` remains the narrow one.

## Why this exists

`tests/fixtures/README.md` explains why the benign canary is synthesized: so that *zero labels is
known-correct by construction*. That reasoning is sound and unchanged. What it does not give is
**coverage**.

`benign.pcap` is 14 packets — two cleartext HTTP flows on port 80, no TLS, no FTP, no SMB, no
SNMP, no unusual ports. It is the standing false-positive review for every wholesale-admitted
source, including `pawpatrules`' 21,464 ungated rules, and it can only ever exercise the handful
of rules that could match two plain HTTP flows.

Measured 2026-08-13 (issue #75): running 23 of these captures against a real nine-feed snapshot
produced **100 labels across 12 captures, 138 source entries, every one from `pawpatrules`** — on
traffic that is benign by construction. `benign.pcap` produced zero against the same snapshot, and
was right to: it contains none of the protocols involved. The canary was not wrong. It was narrow.

One synthetic capture cannot review 85,431 rules spanning every protocol. This corpus is the
answer to that, and it is deliberately *realistic* rather than synthesized — the whole point is
traffic nobody tuned to avoid tripping a rule.

## Origin and licence

Every capture here is taken unmodified from **[OISF/suricata-verify](https://github.com/OISF/suricata-verify)**,
the Suricata project's own protocol-conformance test corpus.

> Copyright (C) 2017-2021 Open Information Security Foundation
> Licensed under the **MIT License**.

The full licence text is at
[`LICENSE.txt`](https://github.com/OISF/suricata-verify/blob/master/LICENSE.txt) in that
repository. MIT permits redistribution, which is why these can live in a public repo when almost
no malware capture can — see the licence discussion in `../README.md`.

The file name is the suricata-verify test directory it came from, so each is traceable to source:
`http-chunked.pcap` is `tests/http-chunked/` there.

| Capture | Protocol exercised |
| --- | --- |
| `http-async-cli`, `http-auth-unrecognized`, `http-chunked`, `http-encoding-identity`, `http-gap-simple`, `http-not09-file`, `http-protocol-inspect-v2`, `http-request-header` | HTTP/1.x, including odd-but-legal encodings and auth |
| `http2-continuation`, `http2-range` | HTTP/2 |
| `ftp-epsv` | FTP with cleartext auth |
| `dns-reversed-tcp-1`, `dns-udp-junkrequest-first` | DNS over TCP and UDP |
| `mqtt311-pub-qos1` | MQTT |
| `dcerpc-issue-7187-01` | DCERPC |
| `krb5-krb5_msg_type` | Kerberos |
| `smb-eicar-file-segmentation-random` | SMB carrying an EICAR test file |

## Why these are *benign* despite what they contain

Two need explaining, because "benign" is doing real work here and a reader should not have to
take it on trust.

**`ftp-epsv` sends an FTP password in clear text.** That is poor hygiene and it is not malicious.
`pawpatrules` sid 3300337 flagged it, correctly as an *observation* — the defect was flabel
promoting that observation to `"verdict": "malicious"` with `"label_basis": "direct"`, which asserts
the flow *is* the attack.

**Resolved 2026-08-14, and this capture no longer produces a label.** Step 11a excludes
`classtype: policy-violation` at admission (436 rules, 0.51% of the ruleset), which removes that
sid — so it is *not* in `tolerated.json`, and an operator triaging a gate failure should not go
looking for it. What survives on this corpus is three sids, listed there with a reason each.

**`smb-eicar-file-segmentation-random` carries an EICAR test file.** EICAR is the industry-standard
"every scanner must detect this" string — deliberately harmless, and by design not malware. It is
kept in the *benign* corpus because flabel labels **malicious flows**, and a test file is not one.

That capture also carries a second, separate finding, recorded here because it is the kind of thing
that gets forgotten: **no admitted source detects the EICAR file.** ET Open ships three active
EICAR rules and the metadata filter excludes all three —

```
sid 2022932  confidence Medium              -> fails the confidence test
sid 2022933  confidence Medium              -> fails the confidence test
sid 2039680  confidence High, severity Minor -> fails the severity test
```

— so the one capture here containing something a detection engine is expected to flag produces
three labels, none of which are about it. That is a *sensitivity* observation, not a
false-positive one, and it is what the missing malicious canary (#24) exists to catch.

## What must never happen to this directory

**Do not add a capture to make a gate pass, and do not remove one to make a gate pass.** The
corpus is a false-positive review; a review curated to agree with the thing it reviews is not one.
If a capture here starts producing labels, the question is whether the rule is wrong or the
capture is genuinely not benign — and answering it means reading the rule, not editing the
directory.

Anything added must clear the same bar as everything above: a licence permitting redistribution in
a public repo, no real personal data, small, and traffic a reasonable reader would call ordinary.
