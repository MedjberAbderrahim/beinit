# 🔧 beinit — Binary Exploitation Init Tool

A `pwninit`-like automation tool designed to bootstrap your binary exploitation challenges faster.  
`beinit` automatically identifies binaries, detects and patches `libc` and interpreter paths, and generates a working `pwntools` exploit template for either local or remote targets.

---

## 🚀 Features

- 🔍 **Auto-detect ELF binary** in the current directory.
- 🧠 **Smart detection** of `libc` and dynamic linker (`ld.so`) files.
- 🧷 **Patch the binary** using `patchelf` with provided or auto-detected `libc` and interpreter.
- 📜 **Generate boilerplate exploit script** using `pwntools`, with local/remote/SSL-ready config.
- 💥 Compatible with most CTF setups and offline reversing sessions.

---

## 📦 Installation

`beinit` depends on:

- [Python 3](https://www.python.org/)
- [`pwntools`](https://docs.pwntools.com/en/stable/)
- [`pyelftools`](https://github.com/eliben/pyelftools)
- `patchelf`

Install requirements via:

```bash
pip install pwntools pyelftools
sudo apt install patchelf
