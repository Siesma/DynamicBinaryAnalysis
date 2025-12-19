import json
import sys
import math

INSTR_WEIGHTS = {
    "add": 1, "sub": 1, "cmp": 1, "test": 1, "and": 1, "or": 1, "xor": 1,
    "mov": 2, "movzx": 2, "movsd": 3, "movsxd": 2, "lea": 2, "push": 2, "pop": 2,
    "jmp": 1, "je": 1, "jne": 1, "jle": 1, "jl": 1, "jg": 1, "jge": 1,
    "mulsd": 5, "divsd": 5, "addsd": 4, "subsd": 4, "pxor": 3, "movapd": 3,
    "call": 0,
    "ret": 0
}

def compute_I(loop, weights):
    I = 0
    for op, count in loop["op_hist"].items():
        weight = weights.get(op, 0)
        I += weight * count
    return I

def mean(values):
    return sum(values) / len(values)

def stddev(values, mu):
    return math.sqrt(sum((x - mu) ** 2 for x in values) / len(values))

def median(values):
    values = sorted(values)
    n = len(values)
    mid = n // 2
    if n % 2 == 0:
        return (values[mid - 1] + values[mid]) / 2
    return values[mid]

def main(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)

    I_vals = []

    print("Per-loop instruction weight I(l):")
    for idx, loop in enumerate(data["loops"]):
        loop_id = f"LOOP_{idx}"
        I_val = compute_I(loop, INSTR_WEIGHTS)
        I_vals.append(I_val)
        print(f"  {loop_id}: {I_val}")

    if not I_vals:
        print("No loops found.")
        return

    mu = mean(I_vals)
    sigma = stddev(I_vals, mu)
    med = median(I_vals)
    min_ = min(I_vals)
    max_ = max(I_vals)

    print("\nSummary statistics over all loops:")
    print(f"  Mean   I(l): {mu:.2f}")
    print(f"  Stddev I(l): {sigma:.2f}")
    print(f"  Median I(l): {med:.2f}")
    print(f"  Min I(l): {min_:.2f}")
    print(f"  Max I(l): {max_:.2f}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 instruction_weight_metric.py loops.json")
        sys.exit(1)

    main(sys.argv[1])

