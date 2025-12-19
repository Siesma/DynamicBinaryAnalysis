import argparse
import json
import os
import math
import traceback
from collections import Counter

import angr
import networkx as nx
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np

def block_info(proj, block):
    hist = Counter()
    has_load = False
    has_store = False
    try:
        if getattr(block, "capstone", None) and getattr(block.capstone, "insns", None):
            for ins in block.capstone.insns:
                m = ins.mnemonic
                hist[m] += 1
                opstr = getattr(ins, "op_str", "") or ""
                if m.startswith("mov") and "[" in opstr:
                    has_load = True
                if m.startswith(("stos", "mov")) and "]" in opstr:
                    has_store = True
    except Exception:
        pass
    return dict(hist), has_load, has_store

def build_cfg(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
    )

    G = nx.DiGraph()
    block_data = {}
    addr_to_func_entry = {}
    functions_by_entry = {}

    for func in cfg.kb.functions.values():
        functions_by_entry[func.addr] = func

    for func in cfg.kb.functions.values():
        for bb_addr in func.block_addrs_set:
            try:
                block = proj.factory.block(bb_addr)
            except Exception:
                continue
            hist, has_load, has_store = block_info(proj, block)
            block_data[bb_addr] = {
                "addr": hex(bb_addr),
                "size": getattr(block, "size", 0),
                "op_hist": hist,
                "has_load": has_load,
                "has_store": has_store,
            }
            G.add_node(bb_addr)
            addr_to_func_entry[bb_addr] = func.addr

        try:
            for src, dst, _ in func.graph.edges(data=True):
                G.add_edge(src.addr, dst.addr)
        except Exception:
            pass

    call_edges = set()
    for bb_addr, b in list(block_data.items()):
        try:
            block = proj.factory.block(bb_addr)
            if getattr(block, "capstone", None) and getattr(block.capstone, "insns", None):
                for ins in block.capstone.insns:
                    if ins.mnemonic == "call":
                        op = getattr(ins, "op_str", "") or ""
                        if "0x" in op:
                            toks = [t for t in op.replace(",", " ").split() if t.startswith("0x")]
                            if toks:
                                try:
                                    target = int(toks[0], 16)
                                    if target in functions_by_entry:
                                        src_func = addr_to_func_entry.get(bb_addr)
                                        if src_func is not None:
                                            call_edges.add((src_func, target))
                                except Exception:
                                    pass
        except Exception:
            pass

    func_graph = nx.DiGraph()
    for entry in functions_by_entry.keys():
        func_graph.add_node(entry)
    for a, b in call_edges:
        func_graph.add_edge(a, b)

    return G, block_data, func_graph, functions_by_entry

def find_loops(G):
    loops = []
    for scc in nx.strongly_connected_components(G):
        if len(scc) > 1:
            loops.append(list(scc))
    return loops

def find_loops_heuristic(G, block_data):
    loops = []
    for addr, b in block_data.items():
        ops = b["op_hist"].keys()
        if any(op in ops for op in ["jle", "jl", "jg", "jge", "jmp", "jne", "je"]):
            for succ in G.successors(addr):
                if succ < addr:
                    loops.append([addr, succ])
    return loops

def loop_statistics(loops, block_data, total_program_insns, threads=8):
    loop_infos = []
    for loop_nodes in loops:
        total_insns = 0
        load_count = 0
        store_count = 0
        op_hist = Counter()
        for addr in loop_nodes:
            b = block_data.get(addr)
            if not b:
                continue
            total_insns += sum(b["op_hist"].values())
            if b["has_load"]:
                load_count += 1
            if b["has_store"]:
                store_count += 1
            op_hist.update(b["op_hist"])
        loop_fraction = total_insns / total_program_insns
        if(total_insns > 1000):
            print(total_program_insns)
            print(total_insns)
            print(loop_fraction)

        loop_infos.append({
            "nodes": [hex(a) for a in loop_nodes],
            "instruction_count": total_insns,
            "loop_fraction": loop_fraction,
            "load_blocks": load_count,
            "store_blocks": store_count,
            "op_hist": dict(op_hist),
        })
    return loop_infos

def collapse_loops(G, loops):
    G_copy = G.copy()

    loop_nodes = set()
    for loop in loops:
        loop_nodes |= set(loop)

    for i, loop in enumerate(loops):
        loop_name = f"LOOP_{i}"
        G_copy.add_node(loop_name)
        for n in loop:
            for pred in list(G_copy.predecessors(n)):
                if pred not in loop:
                    G_copy.add_edge(pred, loop_name)
            for succ in list(G_copy.successors(n)):
                if succ not in loop:
                    G_copy.add_edge(loop_name, succ)
            if n in G_copy:
                G_copy.remove_node(n)

    remaining_nodes = [n for n in G_copy.nodes if not str(n).startswith("LOOP_")]
    undirected = G_copy.subgraph(remaining_nodes).to_undirected()
    components = list(nx.connected_components(undirected))

    for i, comp in enumerate(components):
        block_name = f"BLOCK_{i}"
        G_copy.add_node(block_name)
        for n in comp:
            for pred in list(G_copy.predecessors(n)):
                if pred not in comp:
                    G_copy.add_edge(pred, block_name)
            for succ in list(G_copy.successors(n)):
                if succ not in comp:
                    G_copy.add_edge(block_name, succ)
            if n in G_copy:
                G_copy.remove_node(n)

    return G_copy

def build_loop_connectivity_graph(Gc):
    LG = nx.DiGraph()
    loop_nodes = [n for n in Gc.nodes if str(n).startswith("LOOP_")]
    for ln in loop_nodes:
        LG.add_node(ln)
    for ln in loop_nodes:
        for succ in Gc.successors(ln):
            if str(succ).startswith("LOOP_"):
                LG.add_edge(ln, succ)
    return LG

def compute_reachability(LG):
    reach = {}
    for n in LG.nodes:
        reach[n] = list(nx.descendants(LG, n))
    return reach

def compute_components(LG):
    undirected = LG.to_undirected()
    return [list(c) for c in nx.connected_components(undirected)]

def compute_dominators(LG):
    doms = {}
    for n in LG.nodes:
        doms[n] = list(nx.ancestors(LG, n))
    return doms

def compute_postdominators(LG):
    RG = LG.reverse(copy=True)
    pdoms = {}
    for n in RG.nodes:
        pdoms[n] = list(nx.ancestors(RG, n))
    return pdoms

def compute_parallel_sets(LG, reach, doms, pdoms):
    loops = list(LG.nodes)
    parallel = {l: [] for l in loops}
    for a in loops:
        for b in loops:
            if a == b:
                continue
            if b in reach.get(a, []) or a in reach.get(b, []):
                continue
            if b in doms.get(a, []) or a in doms.get(b, []):
                continue
            if b in pdoms.get(a, []) or a in pdoms.get(b, []):
                continue
            parallel[a].append(b)
    return parallel

def safe_pos_layout(G_sub, seed=42):
    try:
        return nx.spring_layout(G_sub, seed=seed)
    except Exception:
        return nx.circular_layout(G_sub)

def visualize_cfg(G, out_path="cfg_loops_clustered.png"):
    import matplotlib.patches as mpatches
    plt.figure(figsize=(14, 10))
    
    node_colors = ["tomato" if str(n).startswith("LOOP_") else "skyblue" for n in G.nodes]
    pos = safe_pos_layout(G, seed=1)

    sanitized_pos = {}
    MAX_COORD = 1e6
    for n, p in pos.items():
        try:
            x = float(p[0]); y = float(p[1])
        except Exception:
            x, y = np.random.rand()*1e-3, np.random.rand()*1e-3
        if not (math.isfinite(x) and math.isfinite(y)):
            x, y = np.random.rand()*1e-3, np.random.rand()*1e-3
        sanitized_pos[n] = (max(min(x, MAX_COORD), -MAX_COORD), max(min(y, MAX_COORD), -MAX_COORD))

    nx.draw_networkx_edges(G, sanitized_pos, arrows=True, arrowsize=10, width=0.8, alpha=0.6)
    nx.draw_networkx_nodes(G, sanitized_pos, node_color=node_colors, node_size=700, edgecolors="black", linewidths=0.8)
    #nx.draw_networkx_labels(G, sanitized_pos, font_size=8)
    loop_patch = mpatches.Patch(color="tomato", label="Loop / Back-edge Region")
    block_patch = mpatches.Patch(color="skyblue", label="Regular Block (Clustered)")
    plt.legend(handles=[loop_patch, block_patch], loc="upper left", fontsize=8)
    plt.title("CFG with Detected Loops — Grouped by Connectivity", fontsize=14)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved {out_path}")

def visualize_meta_cfg(func_graph, functions_by_entry, region_graph, out_path="meta_cfg.png"):
    import matplotlib.patches as mpatches
    fig, axs = plt.subplots(1, 2, figsize=(18, 9))

    left = axs[0]
    sub_fn = func_graph.copy()
    pos_fn = safe_pos_layout(sub_fn, seed=24)
    colors_fn = []
    for n in sub_fn.nodes():
        colors_fn.append("#9ecae1")
    nx.draw_networkx_edges(sub_fn, pos_fn, ax=left, arrowstyle='->', arrowsize=10, edge_color='gray', alpha=0.7)
    nx.draw_networkx_nodes(sub_fn, pos_fn, ax=left, node_size=600, node_color=colors_fn, edgecolors='black')
    labels_fn = {}
    for n in sub_fn.nodes():
        f = functions_by_entry.get(n)
        if f is not None:
            try:
                name = f.name if getattr(f, "name", None) else hex(n)
            except Exception:
                name = hex(n)
        else:
            name = hex(n)
        labels_fn[n] = (name if len(name) <= 18 else (name[:15] + "..."))
    nx.draw_networkx_labels(sub_fn, pos_fn, labels=labels_fn, ax=left, font_size=7)
    left.set_title("Function-level call graph")
    left.axis("off")

    right = axs[1]
    LG = nx.DiGraph()
    loop_nodes = [n for n in region_graph.nodes if str(n).startswith("LOOP_")]
    for ln in loop_nodes:
        LG.add_node(ln)
    for ln in loop_nodes:
        for succ in region_graph.successors(ln):
            if str(succ).startswith("LOOP_"):
                LG.add_edge(ln, succ)

    pos_reg = safe_pos_layout(LG, seed=99)
    node_colors = ["tomato" for _ in LG.nodes()]
    nx.draw_networkx_edges(LG, pos_reg, ax=right, arrows=True, arrowstyle='->', arrowsize=10, edge_color='gray', alpha=0.6)
    nx.draw_networkx_nodes(LG, pos_reg, node_color=node_colors, node_size=700, edgecolors='black')
    nx.draw_networkx_labels(LG, pos_reg, font_size=8, ax=right)
    right.set_title("Loop-level Meta CFG (LOOP_x only)")
    right.axis("off")

    plt.suptitle("Meta-CFG: Functions (left) and Loop-level Meta (right)", fontsize=16, fontweight="bold")
    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved {out_path}")

def main():
    parser = argparse.ArgumentParser(description="Build CFG, detect loops, produce visualizations and extended loops.json (with connectivity).")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--threads", type=int, default=8, help="Threads assumed for Amdahl estimate")
    args = parser.parse_args()

    binary = args.binary
    threads = args.threads

    print(f"Building CFG for {binary}")
    G, block_data, func_graph, functions_by_entry = build_cfg(binary)
    print(f"Collected {len(G.nodes)} basic blocks, {len(G.edges)} edges")
    print(f"Found {len(func_graph.nodes)} functions, {len(func_graph.edges)} call edges")

    loops = find_loops(G)
    if not loops:
        loops = find_loops_heuristic(G, block_data)
    print(f"Detected {len(loops)} loop(s)")

    total_program_insns = sum(sum(b["op_hist"].values()) for b in block_data.values())
    print(f"Total static instructions (sum of block op_hist): {total_program_insns}")

    loop_info = loop_statistics(loops, block_data, total_program_insns, threads=threads)

    Gc = collapse_loops(G, loops)

    LG = build_loop_connectivity_graph(Gc)
    reach = compute_reachability(LG)
    components = compute_components(LG)
    doms = compute_dominators(LG)
    pdoms = compute_postdominators(LG)
    parallel_sets = compute_parallel_sets(LG, reach, doms, pdoms)

    out_obj = {
        "total_program_instructions": total_program_insns,
        "threads_assumed": threads,
        "loops": loop_info,
        "connectivity": {
            "reachability": reach,
            "loop_components": components,
            "dominators": doms,
            "postdominators": pdoms,
            "parallelizable_sets": parallel_sets
        }
    }

    with open("loops.json", "w") as f:
        json.dump(out_obj, f, indent=2)
    print("Saved loops.json")

    visualize_cfg(Gc, out_path="cfg_loops_clustered.png")

    visualize_meta_cfg(func_graph, functions_by_entry, Gc, out_path="meta_cfg.png")

if __name__ == "__main__":
    main()
