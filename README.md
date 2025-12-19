# Binary Loop Analysis Tool

This repository contains a set of Python scripts for **static analysis of compiled binaries**.  
The tools identify loop regions from binaries and provide structural graphs and instruction-weight metrics.

## Requirements

- Python 3
- angr
- networkx
- matplotlib

## Usage

### 1. Extract loops from a binary

Run the main analysis script on a compiled binary:

```bash
python3 sci_wri.py /path/to/binary
```
This generates a file called:
```bash
loops.json
```
which contains information about detected loops and basic blocks.

### 2. Generate loop graphs
To visualize the detected loop regions as graphs:
```bash
python3 loop_analyser.py /path/to/loops.json
```
This produces graphical representations of the loop structures.

### 3. Compute instruction weight metrics (optional, only useful for pruning)
To compute the instruction-weight-based intensity metric for each loop:
```bash
python3 instruction_weight_metric.py /path/to/loops.json
```
This provides a quantitative measure of the computational importance of each loop.

### Notes
- The analysis works directly on binaries and does not require source code or debug symbols.
- All steps are fully static and deterministic.
