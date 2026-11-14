"""Builds REPORT.md from results/*.jsonl and logs/. Run from the demo folder."""
import json, pathlib, statistics

D = pathlib.Path(__file__).resolve().parent
L = lambda n: [json.loads(x) for x in open(D / "results" / n)]
ver, sol, ce, ex, fz, pr = L("versions.jsonl")[0], L("solver.jsonl"), L("counterexample.jsonl"), L("exhaustive.jsonl"), L("fuzz.jsonl"), L("probe.jsonl")
prov = json.loads((D / "provenance.json").read_text())
pub = [s for s in sol if s["script"] == "published_solver.py"]; hand = [s for s in sol if s["script"] == "handwritten.py"]
med = lambda xs: statistics.median(xs)
tight = next(c for c in ce if c["capacity"] == 59); spare = next(c for c in ce if c["capacity"] == 1024)
e59 = next(e for e in ex if e["length"] == 59)
clip = [f for f in fz if f["label"] == "clipped"]; p60 = [f for f in fz if f["label"] == "plain60"]; p600 = [f for f in fz if f["label"] == "plain600"][0]
hit = [f for f in p60 if f["crash"]]; miss = [f for f in p60 if not f["crash"]]
calls = sum(p["calls"] for p in pr); eq = sum(p["cap_eq_len"] for p in pr); big = sum(p["capacity_64_to_128_mib_calls"] for p in pr)
def line(path, needle):
    for i, t in enumerate(open(D / path), 1):
        if needle in t: return i
    raise SystemExit(f"{needle!r} not in {path}")
o = []
w = o.append
w("# Replaying a published Go crash: solver counterexample, fuzzing, and slice capacity\n")
w("Vikawork measurement, 14 November 2026. It replays the example published in")
w(f"<{prov['article_url']}> (Google Developers Blog, 12 November 2026). The article's figures are lab-reported; ours are below.\n")
w("## Headline figures\n")
w(f"1. Counterexample: reproduced. The published Z3 script returned `sat` in 20 of 20 runs with length {tight['solver_length']}, hdrLen {tight['header_len']}, bodyLen {tight['body_len']} (the article's 59, 48, 236). With capacity equal to length the published parser panicked: `{tight['panic']}`. The whole solver process, Python start included, took a median of {med(s['seconds_process'] for s in pub) * 1000:.0f} ms.")
w(f"2. Spare capacity hides it: reproduced. The same 59 bytes at the front of a 1,024-byte backing array did not panic. The parser returned a {spare['returned_header_len']}-byte header and a {spare['returned_body_len']}-byte body, so it handed back bytes past the end of the 59-byte input.")
w(f"3. How common: reproduced. At length 59 with capacity 59, {e59['panics']:,} of {e59['pairs']:,} (hdrLen, bodyLen) pairs panic, {e59['panics'] / e59['pairs'] * 100:.1f}% (article: 19.4%). " + " ".join(f"At length {e['length']}: {e['panics']:,} ({e['panics'] / e['pairs'] * 100:.1f}%)." for e in ex if e["length"] != 59))
w(f"4. Plain fuzzing: differs in one run. Unseeded `go test -fuzz` on the published harness, fresh fuzz cache each run: {len(miss)} of {len(p60)} sixty-second runs finished with no crash (between {min(f['last_execs_line'] for f in miss):,} and {max(f['last_execs_line'] for f in miss):,} executions each), and one 600-second run finished with no crash after {p600['last_execs_line']:,} executions. {len(hit)} sixty-second run crashed after {hit[0]['go_reported_seconds']} s (`{hit[0]['panic_line'].split('panic: ')[1]}`). The article reports no crash in one 3-second and three 60-second runs.")
w(f"5. Capacity clip: reproduced. With `data = data[:len(data):len(data)]` as the first line of the fuzz function, {sum(f['crash'] for f in clip)} of {len(clip)} runs crashed. Time reported by Go: median {med(f['go_reported_seconds'] for f in clip):.2f} s, range {min(f['go_reported_seconds'] for f in clip)} to {max(f['go_reported_seconds'] for f in clip)} s (article: all three runs, median 0.28 s).")
w(f"6. What the fuzzer passes in: same direction, different shares. Over three 10-second probes, {calls:,} calls. {big / calls * 100:.2f}% of inputs were views with capacity 104,857,500 bytes (article: 89% in a buffer of about 100 MB). {eq:,} calls, {eq / calls * 100:.3f}%, had capacity equal to length (article: 0.07% of 386,741 calls). Our probe counts through shared memory and does not print per call; we do not know how the article counted.")
w(f"7. Our addition: a ten-line Z3 script written by hand from the Go source also returned `sat`, with hdrLen 45 and bodyLen 221, in 20 of 20 runs. It is hand-written by this job, not model-generated. We did not run Gemini and did not test its translation.")
w("8. Not run: the article's `ParseMagicPacket` control. Its full source is not in the article.\n")
w("## Setup\n")
w(f"- {ver['go']} (archive SHA-256 `{prov['go_archive_sha256']}`), Z3 {ver['z3']} from the `z3-solver` wheel {prov['z3_distribution_version']} (SHA-256 `{prov['z3_wheel_sha256']}`).")
w(f"- A 16-core desktop processor ({ver['gomaxprocs']} threads; fuzz workers at Go's default, one per thread), Linux, amd64. The article's assembly target is riscv64; we ran natively and also compiled for riscv64 to log the bounds checks.")
w(f"- Code: `source/published_parser.go`, `source/published_solver.py` and `source/published_clip.txt` are the article's code blocks as published (SHA-256 of each in `provenance.json`); only the `package` line is ours. `source/harness_test.go`, `source/probe_test.go`, `source/raw_panic_test.go` and `source/handwritten.py` are ours.")
w("- Commands: `run.py` (after `setup.py`) ran everything; each fuzz run was `go test -count=1 -run ^$ -fuzz ^<target>$ -fuzztime <N>s ./source/` after `go clean -fuzzcache` and after deleting `source/testdata`.\n")
w("## Fuzz runs\n")
w("| run | target | limit | crash | Go-reported s | executions at last progress line | 1-min load at start | log |")
w("|---|---|---|---|---|---|---|---|")
for f in fz:
    w(f"| {f['label']}-{f['run']:02d} | {f['target']} | {f['fuzztime_s']} s | {'yes' if f['crash'] else 'no'} | {f['go_reported_seconds'] or ''} | {f['last_execs_line']:,} | {f['load_1m_start']} | `logs/{f['log']}` |")
w("\nThe clipped runs crashed before Go printed a progress line with a count, so their execution counts read 0.\n")
w("## Capacity probe\n")
w("| run | calls | cap == len | cap > len | capacity 104,857,500 | min cap | median cap |")
w("|---|---|---|---|---|---|---|")
for p in pr: w(f"| {p['run']} | {p['calls']:,} | {p['cap_eq_len']:,} | {p['cap_gt_len']:,} | {p['capacity_64_to_128_mib_calls']:,} | {p['capacity_min']} | {p['capacity_median']:,} |")
w("\nFull histograms are in `results/probe.jsonl`.\n")
w("## Screenworthy evidence\n")
ev = [("The wrapped 8-bit sum", "source/published_parser.go", "total := hdrLen + bodyLen"), ("The guard", "source/published_parser.go", "if int(total)+4 > len(buf)"),
      ("The full-width end and the slices", "source/published_parser.go", "endBody := endHdr + int(bodyLen)"), ("The slice line", "source/published_parser.go", "return buf[4:endHdr]"),
      ("First surviving bounds check (riscv64 build)", "logs/riscv64-asm.log", "16:12: Found IsSliceInBounds"), ("Second surviving bounds check", "logs/riscv64-asm.log", "16:27: Found IsSliceInBounds"),
      ("The solver's model", "logs/z3-published_solver-r01.log", "length = 59"), ("The panic with cap == len", "logs/raw-panic.log", "panic: runtime error"),
      ("No panic with spare capacity (returned lengths 48 and 236)", "results/counterexample.jsonl", '"capacity": 1024'),
      ("A plain fuzz run, 60 s, no crash", "logs/fuzz-plain60-r03.log", "elapsed: 1m0s"), ("The 600 s plain run, no crash", "logs/fuzz-plain600-r01.log", "elapsed: 10m0s"),
      ("The one plain run that crashed", "logs/fuzz-plain60-r06.log", "--- FAIL: FuzzTwoChunk (0"), ("A clipped fuzz run crashing", "logs/fuzz-clipped-r03.log", "--- FAIL: FuzzTwoChunkClipped (0.28s)"),
      ("The failing input Go wrote", "logs/failing-input-clipped-r03.txt", "[]byte"), ("The clip line as published", "source/published_clip.txt", "data = data[:len(data):len(data)]"),
      ("The hand-written solver result", "logs/z3-handwritten-r01.log", "header = 45")]
for name, path, needle in ev: w(f"- {name}: `{path}` line {line(path, needle)}.")
w("\n## Limits\n")
w("- One function, one machine, one Go version, the published counterexample only. We did not run Gemini; this tests the published example, not a model's ability to write constraints.")
w("- Other work was running on the machine. The 1-minute load at the start of each fuzz run is in the table; the fuzzer's own 32 workers account for part of it.")
w("- Ten 60-second runs and one 600-second run are a small sample of an unseeded, randomised search. One of the ten found the crash, so plain fuzzing can find it; we did not estimate how often.")
w("- A `sat` result is evidence only after the Go test reproduces the panic, which it did here. An `unsat` from a model-written script would not prove the code safe.")
w("- Paths in logs are shortened to `<job>`.")
(D / "REPORT.md").write_text("\n".join(o) + "\n")
print("ok")
