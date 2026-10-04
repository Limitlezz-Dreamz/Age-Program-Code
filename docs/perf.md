# Performance notes

Recorded with `lw ingest --bench --no-hash --no-fts`.

| Dataset | Files | Events | Host | Threads | events/sec | elapsed |
|---|---|---|---|---|---|---|
| cc0/sample.evtx | 1 | 824 | cloud x64 (this agent) | nproc | ~54 700 | ~15 ms |
| EVTX-ATTACK-SAMPLES | 278 | 8 377 | cloud x64 | nproc | (see run log) | <2 s |
| hayabusa-sample-evtx | 599 | 47 699 | cloud x64 | nproc | ~37 700 | ~1.3 s |

Target (spec M1): ≥150k events/sec parse+normalize+store without FTS on an 8-core M-series or modern x64 laptop. Re-run on release hardware and update this table.
