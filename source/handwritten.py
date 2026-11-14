# Source: https://developers.googleblog.com/catch-go-bugs-that-fuzzing-misses-with-gemini-and-a-constraint-solver/
# Job-authored source-only addition, NOT the published model-generated script.
# Written from the Go slice arithmetic before revisiting the published solver; no LLM API called.
from z3 import BitVecs, Solver, ZeroExt, ULE, UGT
header, body = BitVecs('header body', 8)
solver = Solver()
wrapped_end = ZeroExt(8, header + body) + 4
header_end = ZeroExt(8, header) + 4
body_end = header_end + ZeroExt(8, body)
solver.add(ULE(wrapped_end, 59), ULE(header_end, 59), UGT(body_end, 59))
result = solver.check()
print(result)
print(solver.model())
