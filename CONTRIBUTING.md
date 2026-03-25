# Contributing to Network 2.0

<p align="center">
<img src="https://img.shields.io/badge/DSCWoC-2026-blueviolet?style=for-the-badge&logo=rocket" alt="DSCWoC Badge">
<img src="https://img.shields.io/badge/Mission-Open%20Source-ff69b4?style=for-the-badge&logo=github" alt="Mission Badge">
</p>

First off, thank you for considering contributing to Network 2.0! It’s people like you who make open-source tools better for everyone.

---

## Environment Setup
To contribute to this C++ project, ensure your environment meets these requirements:

### Prerequisites
* **Compiler:** C++17 or higher (GCC 9+, Clang 10+, or MSVC 2019+).
* **Build System:** CMake 3.15+.
* **Libraries:**
    - **Linux:** `libpcap-dev`, `build-essential`.
    - **Windows:** [Npcap SDK](https://npcap.com/) and WinPcap compatibility headers.

### **Local Build**

```bash
git clone https://github.com/Nitya-003/network2.0.git
cd network2.0
mkdir build && cd build
cmake ..
make
```

> **Note:** Because this utility performs raw packet capture, you must run the compiled binary with **sudo** (Linux) or as **Administrator** (Windows).

---

## Contribution Workflow
1. **Find an Issue:** Browse the [Issues](https://github.com/Nitya-003/network2.0/issues) tab. If you have a new idea, open an issue first to discuss the implementation.
2. **Fork & Branch:** Fork the repository and create a branch from `main`.
   * `feat/your-feature-name` for new functionality.
   * `fix/issue-description` for bug fixes.
   * `docs/update-info` for documentation changes.
3. **Develop:** Write your code, ensuring it follows our coding standards (see below).
4. **Test:** Verify your changes locally. Ensure that your code does not break the cross-platform build (if possible).
5. **Submit PR:** Open a Pull Request with a clear description of the changes and link the relevant issue (e.g., `Closes #12`).

---

## Coding Standards
To maintain a high-quality codebase, we follow these guidelines:
* **Modern C++:** Use C++17 features where they improve readability or performance (e.g., `std::optional`, `structured bindings`).
* **Naming Conventions:**
    - Classes: `PascalCase` (e.g., `PacketAnalyzer`).
    - Variables/Functions: `camelCase` (e.g., `sourceAddress`, `processPacket()`).
    - Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_PACKET_SIZE`).
* **Memory Management:** Prefer Smart Pointers (`std::unique_ptr`, `std::shared_ptr`) over raw pointers to prevent memory leaks, especially when handling `pcap_t` handles.
* **Documentation:** If you add a new heuristic or command-line flag, update the `README.md` and add comments to the header files.

---

## License
By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
