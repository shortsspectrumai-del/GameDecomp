# Bundled GraphSAGE Model Card — `semantic-family-v1`

The bundled model `gamedecomp/data/gnn_family.json` was trained locally on CPU using PyTorch (`seed=17`, `120` epochs). Runtime inference in GameDecomp uses **only the Python standard library and numeric JSON weights**: it requires no PyTorch installation, GPU, network access, or API key (`--gnn-model builtin`).

## Task & Architecture

Classifies binary functions into six semantic families:
- `arithmetic`
- `bitwise`
- `comparison`
- `float_math`
- `memory_read`
- `memory_write`

The architecture is a 2-layer **GraphSAGE** network with mean neighborhood aggregation, `32` hidden units, and `32` static features extracted from assembly instructions, control-flow graphs (CFG), and ABI metadata. Graph edges are derived from observed call relationships and symmetrized for message passing. It is a structural classifier—not a generative LLM—and does not synthesize source code or arbitrary types.

Input features deliberately exclude symbol names, absolute addresses, labels, source strings, debug types, and `objdump` symbolic comments. Feature normalization statistics (`mean`, `std`) are estimated strictly on the training split; checkpoint selection uses validation macro-F1 and validation cross-entropy loss. The holdout test split is evaluated once on the selected checkpoint.

## Training Corpus & Empirical Results

Trained on original C fixtures compiled across 48 source units with GCC and Clang at `-O0`, `-O1`, and `-O2`, yielding **288 call graphs** and **3,456 functions** across 9 distinct structural template groups. All compiler/optimization/constant variants of any template group are strictly isolated within a single split.

| Split | Call Graphs | Template Groups | Functions | Accuracy | Macro-F1 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **Train** | 180 | 3 | 2,160 | 100.00% | 1.0000 |
| **Validation** | 54 | 3 | 648 | 89.81% | 0.8944 |
| **Test (Holdout)** | **54** | **3** | **648** | **86.27%** | **0.8622** |

- **Majority-class test baseline:** `16.67%` accuracy and `0.0476` macro-F1.
- **Selected checkpoint:** Epoch `69` (initial train loss `1.83157`, final epoch train loss `0.001149`, checkpoint train loss `0.002432`, holdout test loss `5.30397`). Uncalibrated softmax outputs can exhibit high confidence on misclassified out-of-distribution inputs and must not be interpreted as calibrated correctness probabilities.
- **Split contamination audit:** Zero identical full graphs across splits (comparing node order, features, and topology). Exactly 14 identical compact feature vectors appear between train/validation, 2 between train/test, and 5 between validation/test because compact instruction histograms can coincide across distinct short functions.

## Provenance & Reproduction

```bash
python3 -m gamedecomp gnn-demo -o new-training --samples 48 --epochs 120 --seed 17
python3 -m gamedecomp train-gnn dataset.json -o new-model --epochs 120 --seed 17
python3 -m gamedecomp analyze game.so -o results --gnn-model builtin
```

PyTorch is required only for `train-gnn` / `gnn-demo`. Different compiler versions or PyTorch builds may produce slightly different corpus binaries or floating-point weights.

## Scope & Limitations

The training corpus is compact and synthetic; holdout accuracy on this corpus does not imply generalization to obfuscated binaries, arbitrary commercial game engines, or non-x86 architectures. Every GNN prediction is explicitly tagged as `HYPOTHESIS` in reports and never overrides baseline decompilation or promotes unverified source code.

Architectural reference: [GraphSAGE (Hamilton et al., NeurIPS 2017)](https://arxiv.org/abs/1706.02216).
