# Third-Party Notices & External Components

GameDecomp source code is distributed under the **GameDecomp Personal and Non-Commercial Use License** (see [`LICENSE`](LICENSE)). This license applies to the GameDecomp codebase and does not alter the licenses of external toolchains or user-analyzed binaries.

## External Toolchains & Optional Dependencies

GameDecomp distribution packages (`wheel` and `sdist`) do **not** bundle Ghidra, OpenJDK/Temurin, GCC, Clang, GNU binutils, CMake, PyTorch, `pyelftools`, Playwright, Microsoft .NET SDK/Runtime, ILSpy, CFR, or third-party LLM weights. Those remain separate, optional external tools governed by their respective open-source or vendor licenses. Any local copies placed under `./tools/` during development are excluded from distribution packages and Git tracking.

- **Optional `.[console]` Extra (`lz4`):** Uses the `lz4` Python package ([python-lz4](https://github.com/python-lz4/python-lz4)) for decompressing Nintendo Switch NSO segments. `lz4` source code is not bundled in GameDecomp packages. All console binary loaders in GameDecomp are original clean-room format parsers; test fixtures are synthetic and contain no commercial ROMs, firmware, SDK code, or cryptographic keys.
- **Optional `.[types]` Extra (`pyelftools`):** Uses [`pyelftools`](https://github.com/eliben/pyelftools) (public domain) when installed to accelerate DWARF section parsing alongside `readelf`.
- **Optional `.[training]` Extra (`torch`):** Uses PyTorch only when training new GraphSAGE checkpoints (`train-gnn` / `gnn-demo`). Runtime GNN inference uses pure Python standard library code.

## Benchmark Target (`2048.c`)

The reproducible real-game benchmark downloads [`2048.c`](https://github.com/mevdschee/2048.c) by Maurits van der Schee (pinned to commit `90343eb209e84fa9687d596f5d5eecfdf7d4df51`, **MIT License**). The benchmark target source and its MIT license notice are stored locally inside `demo-output/` only when the benchmark script is executed and are not bundled inside the GameDecomp wheel or sdist.

## Bundled GraphSAGE Weights (`gamedecomp/data/gnn_family.json`)

The bundled numeric GraphSAGE checkpoint was trained locally on synthetic C fixtures authored within this repository. Provenance, split isolation, and scope limitations are documented in [`docs/GNN_MODEL_CARD.md`](docs/GNN_MODEL_CARD.md). No third-party pretrained weights or remote LLM outputs are bundled in the package.
