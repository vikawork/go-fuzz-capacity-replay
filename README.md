# Replaying a published Go crash: solver counterexample, fuzzing, and slice capacity

A measurement by [Vikawork](https://vikawork.com/), 14 November 2026. It replays the example in
[Catch Go bugs that fuzzing misses with Gemini and a constraint solver](https://developers.googleblog.com/catch-go-bugs-that-fuzzing-misses-with-gemini-and-a-constraint-solver/)
(Google Developers Blog, 12 November 2026) with Go 1.27.3 and Z3 5.4.1 on one desktop processor.

- The published Z3 script returns the post's 59-byte input (header length 48, body length 236). With capacity equal
  to length the published parser panics: `slice bounds out of range [:288] with capacity 59`. The same bytes with
  spare capacity return without a panic.
- At 59 bytes, 12,740 of 65,536 length pairs panic (19.4%, the post's figure).
- Plain `go test -fuzz`: 9 of 10 sixty-second runs and one 600-second run (597,901,272 executions) found nothing.
  One sixty-second run crashed after 0.39 s on an input with little spare capacity.
- With `data = data[:len(data):len(data)]` at the top of the fuzz function, 10 of 10 runs crashed, median 0.30 s.
- Over three 10-second probes (31,096,722 calls), 99.15% of fuzz inputs arrived with a capacity of 104,857,500
  bytes and 0.012% had capacity equal to length.
- A ten-line Z3 script written by hand from the Go source (`source/handwritten.py`) also finds a crashing input.

We did not run Gemini; this tests the published example, not a model's ability to write constraints. The post's
`ParseMagicPacket` control was not run because its source is not in the post.

[REPORT.md](REPORT.md) has every run, the setup and the limits. `results/` and `logs/` hold the raw output.

## The post's code is not in this repository

The parser, the solver script and the harness line are the post's own code blocks. They are not copied here.
`setup.py` fetches the post and writes them to `source/published_parser.go`, `source/published_solver.py` and
`source/published_clip.txt`; `provenance.json` has the SHA-256 of each block as we fetched it on 14 November 2026.
`source/harness_test.go`, `source/probe_test.go`, `source/raw_panic_test.go` and `source/handwritten.py` are ours.

## Run it

`setup.py` (pinned Go and Z3, verified by hash, installed locally) and then `run.py`; `report.py` builds the
report. They were written inside a larger repository and expect a scratch folder one level up, with a
`download-metadata.json` listing the Go archive and Z3 wheel hashes; adjust the paths at the top to use them
elsewhere.
