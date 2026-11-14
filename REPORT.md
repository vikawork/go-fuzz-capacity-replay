# Replaying a published Go crash: solver counterexample, fuzzing, and slice capacity

Vikawork measurement, 14 November 2026. It replays the example published in
<https://developers.googleblog.com/catch-go-bugs-that-fuzzing-misses-with-gemini-and-a-constraint-solver/> (Google Developers Blog, 12 November 2026). The article's figures are lab-reported; ours are below.

## Headline figures

1. Counterexample: reproduced. The published Z3 script returned `sat` in 20 of 20 runs with length 59, hdrLen 48, bodyLen 236 (the article's 59, 48, 236). With capacity equal to length the published parser panicked: `runtime error: slice bounds out of range [:288] with capacity 59`. The whole solver process, Python start included, took a median of 52 ms.
2. Spare capacity hides it: reproduced. The same 59 bytes at the front of a 1,024-byte backing array did not panic. The parser returned a 48-byte header and a 236-byte body, so it handed back bytes past the end of the 59-byte input.
3. How common: reproduced. At length 59 with capacity 59, 12,740 of 65,536 (hdrLen, bodyLen) pairs panic, 19.4% (article: 19.4%). At length 32: 6,989 (10.7%). At length 64: 13,725 (20.9%). At length 128: 24,125 (36.8%). At length 256: 32,637 (49.8%).
4. Plain fuzzing: differs in one run. Unseeded `go test -fuzz` on the published harness, fresh fuzz cache each run: 9 of 10 sixty-second runs finished with no crash (between 55,607,539 and 62,603,367 executions each), and one 600-second run finished with no crash after 597,901,272 executions. 1 sixty-second run crashed after 0.39 s (`runtime error: slice bounds out of range [:194] with capacity 48`). The article reports no crash in one 3-second and three 60-second runs.
5. Capacity clip: reproduced. With `data = data[:len(data):len(data)]` as the first line of the fuzz function, 10 of 10 runs crashed. Time reported by Go: median 0.30 s, range 0.23 to 1.23 s (article: all three runs, median 0.28 s).
6. What the fuzzer passes in: same direction, different shares. Over three 10-second probes, 31,096,722 calls. 99.15% of inputs were views with capacity 104,857,500 bytes (article: 89% in a buffer of about 100 MB). 3,852 calls, 0.012%, had capacity equal to length (article: 0.07% of 386,741 calls). Our probe counts through shared memory and does not print per call; we do not know how the article counted.
7. Our addition: a ten-line Z3 script written by hand from the Go source also returned `sat`, with hdrLen 45 and bodyLen 221, in 20 of 20 runs. It is hand-written by this job, not model-generated. We did not run Gemini and did not test its translation.
8. Not run: the article's `ParseMagicPacket` control. Its full source is not in the article.

## Setup

- go version go1.27.3 linux/amd64 (archive SHA-256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`), Z3 5.4.1 from the `z3-solver` wheel 5.4.1.0 (SHA-256 `e680ce083683abca5d07c3e55c2f620ff9a29cb91c548eeeea27ae29e8060522`).
- A 16-core desktop processor (32 threads; fuzz workers at Go's default, one per thread), Linux, amd64. The article's assembly target is riscv64; we ran natively and also compiled for riscv64 to log the bounds checks.
- Code: `source/published_parser.go`, `source/published_solver.py` and `source/published_clip.txt` are the article's code blocks as published (SHA-256 of each in `provenance.json`); only the `package` line is ours. `source/harness_test.go`, `source/probe_test.go`, `source/raw_panic_test.go` and `source/handwritten.py` are ours.
- Commands: `run.py` (after `setup.py`) ran everything; each fuzz run was `go test -count=1 -run ^$ -fuzz ^<target>$ -fuzztime <N>s ./source/` after `go clean -fuzzcache` and after deleting `source/testdata`.

## Fuzz runs

| run | target | limit | crash | Go-reported s | executions at last progress line | 1-min load at start | log |
|---|---|---|---|---|---|---|---|
| clipped-01 | FuzzTwoChunkClipped | 60 s | yes | 0.31 | 0 | 3.97 | `logs/fuzz-clipped-r01.log` |
| clipped-02 | FuzzTwoChunkClipped | 60 s | yes | 0.31 | 0 | 3.81 | `logs/fuzz-clipped-r02.log` |
| clipped-03 | FuzzTwoChunkClipped | 60 s | yes | 0.28 | 0 | 3.81 | `logs/fuzz-clipped-r03.log` |
| clipped-04 | FuzzTwoChunkClipped | 60 s | yes | 0.24 | 0 | 3.81 | `logs/fuzz-clipped-r04.log` |
| clipped-05 | FuzzTwoChunkClipped | 60 s | yes | 0.23 | 0 | 3.81 | `logs/fuzz-clipped-r05.log` |
| clipped-06 | FuzzTwoChunkClipped | 60 s | yes | 1.23 | 0 | 3.81 | `logs/fuzz-clipped-r06.log` |
| clipped-07 | FuzzTwoChunkClipped | 60 s | yes | 0.27 | 0 | 3.81 | `logs/fuzz-clipped-r07.log` |
| clipped-08 | FuzzTwoChunkClipped | 60 s | yes | 0.32 | 0 | 3.81 | `logs/fuzz-clipped-r08.log` |
| clipped-09 | FuzzTwoChunkClipped | 60 s | yes | 0.28 | 0 | 3.81 | `logs/fuzz-clipped-r09.log` |
| clipped-10 | FuzzTwoChunkClipped | 60 s | yes | 0.31 | 0 | 3.81 | `logs/fuzz-clipped-r10.log` |
| plain60-01 | FuzzTwoChunk | 60 s | no |  | 62,118,683 | 6.15 | `logs/fuzz-plain60-r01.log` |
| plain60-02 | FuzzTwoChunk | 60 s | no |  | 62,491,855 | 30.6 | `logs/fuzz-plain60-r02.log` |
| plain60-03 | FuzzTwoChunk | 60 s | no |  | 60,888,387 | 41.42 | `logs/fuzz-plain60-r03.log` |
| plain60-04 | FuzzTwoChunk | 60 s | no |  | 62,199,939 | 46.72 | `logs/fuzz-plain60-r04.log` |
| plain60-05 | FuzzTwoChunk | 60 s | no |  | 62,426,848 | 48.96 | `logs/fuzz-plain60-r05.log` |
| plain60-06 | FuzzTwoChunk | 60 s | yes | 0.39 | 171,723 | 51.24 | `logs/fuzz-plain60-r06.log` |
| plain60-07 | FuzzTwoChunk | 60 s | no |  | 62,603,367 | 51.24 | `logs/fuzz-plain60-r07.log` |
| plain60-08 | FuzzTwoChunk | 60 s | no |  | 62,469,745 | 48.42 | `logs/fuzz-plain60-r08.log` |
| plain60-09 | FuzzTwoChunk | 60 s | no |  | 61,802,525 | 47.57 | `logs/fuzz-plain60-r09.log` |
| plain60-10 | FuzzTwoChunk | 60 s | no |  | 55,607,539 | 48.01 | `logs/fuzz-plain60-r10.log` |
| plain600-01 | FuzzTwoChunk | 600 s | no |  | 597,901,272 | 53.08 | `logs/fuzz-plain600-r01.log` |

The clipped runs crashed before Go printed a progress line with a count, so their execution counts read 0.

## Capacity probe

| run | calls | cap == len | cap > len | capacity 104,857,500 | min cap | median cap |
|---|---|---|---|---|---|---|
| 1 | 10,389,332 | 1,029 | 10,388,303 | 10,385,351 | 2 | 104,857,500 |
| 2 | 10,393,156 | 1,026 | 10,392,130 | 10,136,791 | 2 | 104,857,500 |
| 3 | 10,314,234 | 1,797 | 10,312,437 | 10,309,051 | 2 | 104,857,500 |

Full histograms are in `results/probe.jsonl`.

## Screenworthy evidence

- The wrapped 8-bit sum: `source/published_parser.go` line 10.
- The guard: `source/published_parser.go` line 11.
- The full-width end and the slices: `source/published_parser.go` line 15.
- The slice line: `source/published_parser.go` line 16.
- First surviving bounds check (riscv64 build): `logs/riscv64-asm.log` line 123.
- Second surviving bounds check: `logs/riscv64-asm.log` line 124.
- The solver's model: `logs/z3-published_solver-r01.log` line 1.
- The panic with cap == len: `logs/raw-panic.log` line 2.
- No panic with spare capacity (returned lengths 48 and 236): `results/counterexample.jsonl` line 2.
- A plain fuzz run, 60 s, no crash: `logs/fuzz-plain60-r03.log` line 22.
- The 600 s plain run, no crash: `logs/fuzz-plain600-r01.log` line 202.
- The one plain run that crashed: `logs/fuzz-plain60-r06.log` line 4.
- A clipped fuzz run crashing: `logs/fuzz-clipped-r03.log` line 5.
- The failing input Go wrote: `logs/failing-input-clipped-r03.txt` line 2.
- The clip line as published: `source/published_clip.txt` line 4.
- The hand-written solver result: `logs/z3-handwritten-r01.log` line 2.

## Limits

- One function, one machine, one Go version, the published counterexample only. We did not run Gemini; this tests the published example, not a model's ability to write constraints.
- Other work was running on the machine. The 1-minute load at the start of each fuzz run is in the table; the fuzzer's own 32 workers account for part of it.
- Ten 60-second runs and one 600-second run are a small sample of an unseeded, randomised search. One of the ten found the crash, so plain fuzzing can find it; we did not estimate how often.
- A `sat` result is evidence only after the Go test reproduces the panic, which it did here. An `unsat` from a model-written script would not prove the code safe.
- Paths in logs are shortened to `<job>`.
