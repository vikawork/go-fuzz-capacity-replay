"""Runs the measurements for the Go/Z3 demo. Toolchains are local to this folder; CPU only; nice 10."""
import json, os, pathlib, re, shutil, statistics, subprocess, sys, time

os.nice(10)
ROOT = pathlib.Path(__file__).resolve().parent
DEMO = ROOT / "demo"
RES, LOGS = DEMO / "results", DEMO / "logs"
for d in (RES, LOGS): d.mkdir(exist_ok=True)
GO = ROOT / "toolchains/go1.27.3/go/bin/go"
PY = ROOT / "venv/bin/python"
ENV = os.environ | {"GOROOT": str(GO.parents[1]), "GOPATH": str(ROOT / "gopath"), "GOCACHE": str(ROOT / "gocache"),
                    "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOTELEMETRY": "off", "HOME": str(ROOT / "home")}
(ROOT / "home").mkdir(exist_ok=True)
PKG = "./source/"
TESTDATA = DEMO / "source/testdata"


def sh(args, log=None, env=ENV, timeout=None):
    t0 = time.monotonic()
    p = subprocess.run([str(a) for a in args], cwd=DEMO, env=env, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout + p.stderr).replace(str(ROOT), "<job>")
    if log: (LOGS / log).write_text(out)
    return p.returncode, out, time.monotonic() - t0


def jsonl(name, rows):
    with open(RES / name, "w") as f:
        for r in rows: f.write(json.dumps(r) + "\n")


def load(): return float(open("/proc/loadavg").read().split()[0])


# --- versions and assembly
_, gov, _ = sh([GO, "version"]); _, z3v, _ = sh([PY, "-c", "import z3;print(z3.get_version_string())"])
jsonl("versions.jsonl", [{"go": gov.strip(), "z3": z3v.strip(), "gomaxprocs": os.cpu_count()}])
sh([GO, "build", "-gcflags=-S -d=ssa/check_bce/debug=1", PKG], "riscv64-asm.log", ENV | {"GOOS": "linux", "GOARCH": "riscv64"})
sh([GO, "build", "-gcflags=-d=ssa/check_bce/debug=1", PKG], "amd64-bce.log")

# --- A: the published solver script, 20 runs; the hand-written one, 20 runs
rows = []
for script in ("published_solver.py", "handwritten.py"):
    for i in range(20):
        rc, out, dt = sh([PY, f"source/{script}"], f"z3-{script[:-3]}-r{i + 1:02d}.log" if i == 0 else None)
        rows.append({"script": script, "run": i + 1, "exit": rc, "seconds_process": round(dt, 4), "output": out.strip()})
jsonl("solver.jsonl", rows)
model = rows[0]["output"]
vals = dict(re.findall(r"(\w+) = (\d+)", model))
hlen, blen, length = int(vals["hdrLen8"]), int(vals["bodyLen8"]), int(vals["length"])
rc, out, _ = sh([GO, "test", "-count=1", "-run", "TestCounterexample|TestExhaustive", "-v", PKG], "counterexample-and-exhaustive.log",
                ENV | {"HLEN": str(hlen), "BLEN": str(blen)})
recs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
jsonl("counterexample.jsonl", [dict(r, solver_length=length) for r in recs if r["kind"] == "counterexample"])
jsonl("exhaustive.jsonl", [r for r in recs if r["kind"] == "exhaustive"])
# the raw panic, uncaught, for the screen
(DEMO / "source/raw_panic_test.go").write_text('// Job-authored: calls the published parser with the published counterexample and lets the panic through.\npackage demo\n\nimport "testing"\n\nfunc TestRawPanic(t *testing.T) {\n\tParseTwoChunkFrame(frame(59, 59, 48, 236))\n}\n')
sh([GO, "test", "-count=1", "-run", "TestRawPanic", PKG], "raw-panic.log")


def fuzz(target, seconds, label, run):
    shutil.rmtree(TESTDATA, ignore_errors=True)
    sh([GO, "clean", "-fuzzcache"])
    l0 = load()
    log = f"fuzz-{label}-r{run:02d}.log"
    rc, out, dt = sh([GO, "test", "-count=1", "-run", "^$", "-fuzz", f"^{target}$", "-fuzztime", f"{seconds}s", PKG], log)
    execs = [int(x) for x in re.findall(r"execs: (\d+)", out)]
    fail = re.search(r"--- FAIL: \w+ \(([\d.]+)s\)", out)
    saved = None
    files = list(TESTDATA.rglob("*")) if TESTDATA.exists() else []
    files = [f for f in files if f.is_file()]
    if files:
        dest = LOGS / f"failing-input-{label}-r{run:02d}.txt"; shutil.copy(files[0], dest); saved = dest.name
    return {"label": label, "target": target, "run": run, "fuzztime_s": seconds, "crash": bool(fail), "go_reported_seconds": float(fail.group(1)) if fail else None,
            "wall_seconds": round(dt, 2), "last_execs_line": execs[-1] if execs else None, "exit": rc, "load_1m_start": l0, "log": log, "failing_input": saved,
            "panic_line": next((l.strip() for l in out.splitlines() if "panic:" in l or "slice bounds" in l), None)}


rows = []
for i in range(10): rows.append(fuzz("FuzzTwoChunkClipped", 60, "clipped", i + 1)); print(rows[-1], flush=True)
for i in range(10): rows.append(fuzz("FuzzTwoChunk", 60, "plain60", i + 1)); print(rows[-1], flush=True)
rows.append(fuzz("FuzzTwoChunk", 600, "plain600", 1)); print(rows[-1], flush=True)
jsonl("fuzz.jsonl", rows)

# --- F: what the fuzzer hands the callback
rows = []
for i in range(3):
    shutil.rmtree(TESTDATA, ignore_errors=True); sh([GO, "clean", "-fuzzcache"])
    pf = ROOT / f"probe-{i + 1}.bin"
    e = ENV | {"GOSOLVER_PROBE_FILE": str(pf)}
    sh([GO, "test", "-count=1", "-run", "TestProbeFileInit", PKG], env=e)
    l0 = load()
    sh([GO, "test", "-count=1", "-run", "^$", "-fuzz", "^FuzzCapacityProbe$", "-fuzztime", "10s", PKG], f"probe-r{i + 1}.log", e)
    rc, out, _ = sh([GO, "test", "-count=1", "-run", "TestProbeFileSummary", "-v", PKG], env=e)
    rec = next(json.loads(l) for l in out.splitlines() if l.startswith("{"))
    rows.append(dict(rec, run=i + 1, load_1m_start=l0)); pf.unlink()
jsonl("probe.jsonl", rows)
shutil.rmtree(TESTDATA, ignore_errors=True)
print("done", flush=True)
