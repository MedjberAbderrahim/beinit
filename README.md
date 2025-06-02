# beinit — Binary Exploitation Init Tool

A `pwninit`-like automation tool designed to bootstrap your binary exploitation challenges faster.  
`beinit` automatically identifies binaries, detects and patches `libc` and interpreter paths, and generates a working `pwntools` exploit template for either local or remote targets.

---

## Features

- **Auto-detect executable ELF binaries** in the current working directory.
- **Heuristics for detecting `libc.so` and dynamic loader (`ld.so`)**.
- **Patches binaries** with auto-detected or explicitely specified `libc` and interpreter using `patchelf`.
- **Generates customizable `pwntools` exploit scripts**:
  - Works locally or with remote/SSL targets.
  - Optional checksec and custom output path.
- **Can be used with no parameters for generic script setup, works for most cases** Just like pwninit.
- **Supports shell tab-completion** via `argcomplete`.

---

## Installation

You can setup and install beinit via:

```bash
# Python3 Required packages
sudo apt install python3
sudo apt install python3-pwntools python3-pyelftools patchelf python3-argcomplete

# For argcomplete autocompletion, if it isn't already set
sudo activate-global-python-argcomplete

git clone https://github.com/MedjberAbderrahim/beinit.git
```

## Usage

```bash
./beinit [-h] [--target TARGET] [--port PORT] [--checksec] [--ssl] [--local] [--remote] [--no-script] [--libc LIBC] [--interpreter INTERPRETER] [--no-patching] [--output OUTPUT] [--binary BINARY]
```

## Notes
- If multiple ELF binaries or libc candidates are present, you’ll get a warning and auto-detection will be skipped.
- THe script automatically backups the original binary to \<binary\>.bak before patching.
- For the script to work globally, check the [Global Installation](#global-installation) section

## Global Installation
You can use the script from whenever you want in your system, by executing the following commands:
```bash
cd beinit
sudo chown root:root ./beinit
sudo chmod 755 ./beinit
cp ./beinit /usr/bin/
```

you can now access it directly as any other linux command:
```bash
beinit --binary <BINARY-NAME> 
```

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details