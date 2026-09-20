# ship-go

[![Helianthus fork CI](https://github.com/Project-Helianthus/helianthus-ship-go/actions/workflows/default.yml/badge.svg?branch=helianthus-v0.6)](https://github.com/Project-Helianthus/helianthus-ship-go/actions/workflows/default.yml?query=branch%3Ahelianthus-v0.6)
[![Upstream build (main)](https://github.com/enbility/ship-go/actions/workflows/default.yml/badge.svg?branch=main)](https://github.com/enbility/ship-go/actions/workflows/default.yml?query=branch%3Amain)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4)](https://godoc.org/github.com/enbility/ship-go)
[![Coverage Status](https://coveralls.io/repos/github/enbility/ship-go/badge.svg?branch=main)](https://coveralls.io/github/enbility/ship-go?branch=main)
[![Go report](https://goreportcard.com/badge/github.com/enbility/ship-go)](https://goreportcard.com/report/github.com/enbility/ship-go)
[![CodeFactor](https://www.codefactor.io/repository/github/enbility/ship-go/badge)](https://www.codefactor.io/repository/github/enbility/ship-go)

## Temporary downstream fork status

This repository is a temporary downstream dependency of Project Helianthus. It
is not a Helianthus product layer and owns no Helianthus semantic policy.

Status inspected **20 September 2026**:

| Item | Evidence |
| --- | --- |
| Upstream | [`enbility/ship-go`](https://github.com/enbility/ship-go), current default branch [`dev`](https://github.com/enbility/ship-go/tree/72fc3ff0f01b0b8e9e3677036e674028389678a4). |
| Upstream release baseline | [`v0.6.0`](https://github.com/enbility/ship-go/tree/v0.6.0), commit [`760c312bf723d726d8882af3bb06650ddcd11ca9`](https://github.com/enbility/ship-go/commit/760c312bf723d726d8882af3bb06650ddcd11ca9). This is the upstream work already contained in the fork baseline. |
| Active Helianthus branch | [`helianthus-v0.6`](https://github.com/Project-Helianthus/helianthus-ship-go/tree/helianthus-v0.6), inspected at [`9d38bfe04d57e7c8c73c59c1ddfc9b521e5045b0`](https://github.com/Project-Helianthus/helianthus-ship-go/commit/9d38bfe04d57e7c8c73c59c1ddfc9b521e5045b0). It is the fork's default and maintained dependency branch. |
| Fork CI | [`Default`](https://github.com/Project-Helianthus/helianthus-ship-go/actions/workflows/default.yml?query=branch%3Ahelianthus-v0.6) runs for pushes to `helianthus-v0.6` and for pull requests; the badge above targets that exact workflow and branch. |
| License | The inherited [MIT license](./LICENSE) remains in force; this status block changes no license. |
| Local-only divergence | The immutable [`v0.6.0...9d38bfe` comparison](https://github.com/Project-Helianthus/helianthus-ship-go/compare/760c312bf723d726d8882af3bb06650ddcd11ca9...9d38bfe04d57e7c8c73c59c1ddfc9b521e5045b0) contains 21 fork commits. At inspection, `git cherry upstream/dev helianthus-v0.6` marked all 21 as absent by patch identity from upstream `dev`; upstream `dev` had advanced separately by 222 commits. No compatibility or superset relationship is inferred. |
| Why the fork remains | Helianthus consumers still depend on generic downstream APIs and lifecycle behavior for pre-dial authorization, controlled candidate selection/retry, scoped discovery and transient PIN outcomes, and a detached native discovery snapshot. These capabilities are local-only in the comparison above. |
| Upstream proposal and acceptance | No upstream proposal is linked for this exact 21-commit series. Whether upstream would accept any individual capability is **unknown**. Local commits are not presented as merged, proposed, rejected, or scheduled upstream work. |
| Return condition | Return to an upstream release only after it provides the required equivalent capabilities, the downstream consumers are migrated off the fork module path, and the resulting dependency passes their normal compatibility and CI gates. No return version or date is currently established. |

The counts and upstream `dev` revision are an inspection snapshot. Re-run the
comparison before using them for a dependency update; this README does not
authorize an upgrade or upstream submission.

This library provides an implementation of SHIP 1.0.1 in [go](https://golang.org), which is part of the [EEBUS](https://eebus.org) specification.

Basic understanding of the EEBUS concepts SHIP and SPINE to use this library is required. Please check the corresponding specifications on the [EEBUS specifications and media website](https://www.eebus.org/specifications-media/).

This repository was started as part of the [eebus-go](https://github.com/enbility/eebus-go) before it was moved into its own repository and this separate go package.

## Overview

Includes:

- Certificate handling
- mDNS, incl. avahi support (recommended)
- Websocket server and client
- Connection handling, including reconnection and double connections
- Handling of device pairing
- SHIP handshake
- Logging which is also used by [spine-go](https://github.com/enbility/spine-go) and [eebus-go](https://github.com/enbility/eebus-go)

## Implementation notes

- Double connection handling is not implemented according to SHIP 12.2.2. Instead the connection initiated by the higher SKI will be kept. Much simpler and always works
- PIN Verification is _NOT_ supported other than SHIP 13.4.4.3.5.1 _"none"_ PIN state is supported!
- Access Methods SHIP 13.4.6 only supports the most basic scenario and only works after PIN verification state is completed.
- Supported registration mechanisms (SHIP 5):
  - auto accept (without any interaction mechanism!)
  - user verification
