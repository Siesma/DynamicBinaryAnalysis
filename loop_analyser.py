import json
import matplotlib.pyplot as plt
import networkx as nx
from collections import Counter
import os
import sys

# Heavily depends on application and has to be administered manually

MIN_COMPUTE_RATIO = 0.5
MIN_INSTRUCTION_COUNT = 15


def should_prune_loop(insn_count, compute_ratio):
    if compute_ratio < MIN_COMPUTE_RATIO:
        return True
    if insn_count < MIN_INSTRUCTION_COUNT:
        return True
    return False


def visualize_loop(loop, idx):
    nodes = loop["nodes"]
    insn_count = loop["instruction_count"]
    load_blocks = loop["load_blocks"]
    store_blocks = loop["store_blocks"]
    op_hist = loop["op_hist"]

    mem_blocks = load_blocks + store_blocks
    compute_ops = sum(v for k, v in op_hist.items()
                      if k not in ["mov", "movq", "movsd", "lea"])
    mem_ops = sum(v for k, v in op_hist.items()
                  if k in ["mov", "movq", "movsd", "lea"])
    compute_ratio = compute_ops / (mem_ops + 1e-6)

    prune_flag = should_prune_loop(insn_count, compute_ratio)
    prune_label = "PRUNE" if prune_flag else "KEEP"

    G = nx.DiGraph()
    for i in range(len(nodes) - 1):
        G.add_edge(nodes[i], nodes[i + 1])
    if len(nodes) > 2:
        G.add_edge(nodes[-1], nodes[0])

    pos = nx.circular_layout(G)
    colors = ["tomato" if i == len(nodes) - 1 else "skyblue"
              for i in range(len(nodes))]

    fig, axs = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle(
        f"Loop {idx} Summary — [{prune_label}]",
        fontsize=14,
        fontweight="bold"
    )

    nx.draw(
        G,
        pos,
        ax=axs[0],
        node_color=colors,
        with_labels=True,
        node_size=1000,
        font_size=7,
        arrowsize=12,
        edgecolors="black"
    )
    axs[0].set_title("Loop Control Flow (approx.)")
    axs[0].axis("off")

    top_ops = Counter(op_hist).most_common(10)
    ops, counts = zip(*top_ops) if top_ops else ([], [])
    axs[1].barh(ops, counts, color="cornflowerblue")
    axs[1].invert_yaxis()
    axs[1].set_title("Top Instructions")
    axs[1].set_xlabel("Count")

    text = (
        f"Total Instructions: {insn_count}\n"
        f"Load Blocks: {load_blocks}\n"
        f"Store Blocks: {store_blocks}\n"
        f"Memory Blocks: {mem_blocks}\n"
        f"Compute/Memory Ratio: {compute_ratio:.2f}\n"
        f"PRUNE?  {prune_label}"
    )
    axs[1].text(
        1.05,
        0.5,
        text,
        transform=axs[1].transAxes,
        fontsize=8,
        verticalalignment="center",
        bbox=dict(boxstyle="round,pad=0.4", fc="whitesmoke", ec="gray")
    )

    plt.tight_layout()
    os.makedirs("loop_figs", exist_ok=True)

    out_path = os.path.join(
        "loop_figs",
        f"loop_{idx}_{prune_label}.png"
    )

    plt.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)

    print(f"Saved {out_path}")


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python3 loop_analyser.py loops.json")
        sys.exit(1)

    loops_file = sys.argv[1]
    with open(loops_file) as f:
        loops = json.load(f)
    loops = loops["loops"]
    print(f"Loaded {len(loops)} loops from {loops_file}")
    for i, loop in enumerate(loops):
        visualize_loop(loop, i)
