#!/usr/bin/env python3

from pwn import *
import argparse
import os
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
from sys import stderr
import subprocess

def validate_args(args):
    if args.local and args.remote:
        raise ValueError("Cannot specify both --local and --remote")
    if args.local:
        if args.ssl:
            print("[-] Warning: SSL flag ignored for local connections", file=stderr)
        if args.target:
            print("[-] Warning: Host IP flag ignored for local connections", file=stderr)
        if args.port:
            print("[-] Warning: Host Port flag ignored for local connections", file=stderr)

def generateScript(args):
    connection_segment = ""
    if args.local:
        connection_segment = f"p = process(\"{args.binary}\")"
    elif args.remote:
        connection_segment = \
f"""HOST = "{args.target if args.target else ''}"
PORT = {args.port if args.port else 0}
p = remote(HOST, PORT{", ssl=True" * args.ssl})
"""
    else:
        connection_segment = \
f"""if args.REMOTE:
    HOST = "{args.target if args.target else ''}"
    PORT = {args.port if args.port else 0}
    p = remote(HOST, PORT{", ssl=True" * args.ssl})
else:
    p = process("{args.binary}")
"""

    chall = f"exe = ELF(\"{args.binary}\", checkseck={args.checksec})\n"
    libc = f"libc = ELF(\"{args.libc}\", checkseck=false)\n" * (args.libc is not None)
    interpreter = f"ldd = ELF(\"{args.interpreter}\", checkseck=false)\n" * (args.interpreter is not None)

    script = \
f"""#!/usr/bin/env python3

from pwn import *

{chall}{libc}{interpreter}
{connection_segment}

p.interactive()
"""
    return script

def detect_chall(filepath):
    try:
        f = open(filepath, 'rb')

        # Check magic number
        if f.read(4) != b'\x7fELF':
            return False

        f.seek(0)
        elf = ELFFile(f)

        # Check it's an executable (ET_EXEC or ET_DYN)
        if elf.header['e_type'] not in ['ET_EXEC', 'ET_DYN']:
            return False

        # Check it has an INTERP segment (typical for executables)
        has_interp = any(seg.header.p_type == 'PT_INTERP' for seg in elf.iter_segments())

        # Shared libraries usually don't have INTERP but executables do; However, some PIE executables might be ET_DYN like shared libraries; So we need additional checks
        # Check for executable segments
        has_executable_segments = any(
            seg.header.p_flags & SH_FLAGS.SHF_EXECINSTR
            for seg in elf.iter_segments()
            if seg.header.p_type == 'PT_LOAD'
        )

        return has_interp or has_executable_segments

    except Exception:
        return False

def getBinaryPath() -> str:
    entries = os.scandir('.')
    candidates = []

    for entry in entries:
        if entry.is_file() and detect_chall(entry.path):
            candidates.append(entry.path)
    
    if len(candidates) > 1:
        print("Too many candidate ELF chall executables in current directory.", file=stderr)
        exit(1)
    elif len(candidates) == 0:
        print("No candidate ELF chall executable found in current directory.", file=stderr)
        exit(1)
    
    return os.path.abspath(candidates[0])

def is_libc(filepath: str) -> bool:
    """Check if a file is a libc shared library"""
    try:
        f = open(filepath, 'rb')
        # Check ELF magic number
        if f.read(4) != b'\x7fELF':
            return False
            
        f.seek(0)
        elf = ELFFile(f)
        
        # Check it's a shared library (ET_DYN)
        if elf.header['e_type'] != 'ET_DYN':
            return False
            
        # Check for common libc patterns in filename
        filename = os.path.basename(filepath).lower()
        if ('libc.so' in filename or 
            'libc-' in filename or 
            filename.startswith('libc.')):
            return True
            
        # Additional checks for libc characteristics
        has_gnu_libc = False
        has_libc_functions = False
        
        # Check for GNU C Library note
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_NOTE':
                for note in segment.iter_notes():
                    if note.n_type == 'NT_GNU_ABI_TAG' and note['abi'] == 'GNU':
                        has_gnu_libc = True
        
        # Check for common libc functions
        symtab = elf.get_section_by_name('.dynsym')
        if symtab:
            for sym in symtab.iter_symbols():
                if sym.name in ['__libc_start_main', 'malloc', 'free', 'printf']:
                    has_libc_functions = True
                    break
        
        return has_gnu_libc and has_libc_functions
            
    except Exception:
        return False

def detect_libc() -> str:
    entries = os.scandir('.')
    candidates = []

    for entry in entries:
        if entry.is_file() and is_libc(entry.path):
            candidates.append(entry.path)
    
    if len(candidates) > 1:
        print("Too many candidate libc executables in current directory, add option --no-patching or explicitely specify a libc, ignoring libc patching...", file=stderr)
        return None
    elif len(candidates) == 0:
        print("No candidate libc executable found in current directory, ignoring libc patching...")
        return None
    
    return os.path.abspath(candidates[0])

def is_interpreter(filepath: str) -> bool:
    try:
        with open(filepath, 'rb') as f:
            # Check ELF magic number
            if f.read(4) != b'\x7fELF':
                return False
                
            f.seek(0)
            elf = ELFFile(f)
            
            # Check it's a shared library (ET_DYN)
            if elf.header['e_type'] != 'ET_DYN':
                return False
                
            # Check for common interpreter patterns in filename
            filename = os.path.basename(filepath).lower()
            if ('ld-linux' in filename or 
                'ld.so' in filename or
                'ld64.so' in filename or
                filename.startswith('ld-') or
                'ld.' in filename):
                return True
                
            # Additional checks for interpreter characteristics
            has_interpreter_notes = False
            has_loader_functions = False
            
            # Check for interpreter-specific notes
            for segment in elf.iter_segments():
                if segment.header.p_type == 'PT_NOTE':
                    for note in segment.iter_notes():
                        if note.n_type == 'NT_GNU_ABI_TAG' and note['abi'] == 'GNU':
                            has_interpreter_notes = True
            
            # Check for loader-specific symbols
            symtab = elf.get_section_by_name('.dynsym')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name in ['_dl_start', '_dl_runtime_resolve', '__libc_start_main']:
                        has_loader_functions = True
                        break
            
            return has_interpreter_notes and has_loader_functions
            
    except Exception:
        return False

def detect_interpreter() -> str:
    entries = os.scandir('.')
    candidates = []

    for entry in entries:
        if entry.is_file() and is_interpreter(entry.path):
            candidates.append(entry.path)
    
    if len(candidates) > 1:
        print("Too many candidate linux interpreter executables in current directory, add option --no-patching or explicitely specify an interpreter, ignoring interpreter patching...", file=stderr)
        return None
    elif len(candidates) == 0:
        print("No candidate linux interpreter executable found in current directory, ignoring interpreter patching...")
        return None
    
    return os.path.abspath(candidates[0])

# def patch_binary(binary: str, libc: str = None, interpreter: str = None):
def patch_binary(args):
    args.binary = os.path.abspath(args.binary)

    try:
        subprocess.run([
            '/usr/bin/cp',
            args.binary,
            f"{args.binary}.bak"
        ], check=True)
        print(f"Backed up bianry to {args.binary}.bak")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create backup: {e}", file=sys.stderr)
    
    args.libc = os.path.abspath(args.libc) if args.libc else detect_libc()
    args.interpreter = os.path.abspath(args.interpreter) if args.interpreter else detect_interpreter()

    if args.libc is None and args.interpreter is None:
        print("No libc or interpreter specified/found - skipping patching")
        return
    
    # Build patchelf command
    try:
        cmd = ['/usr/bin/patchelf']
        
        if args.libc:
            cmd.extend(['--set-rpath', os.path.dirname(args.libc)])
        
        if args.interpreter:
            cmd.extend(['--set-interpreter', args.interpreter])
        
        cmd.append(args.binary)
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Patching failed: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description='pwninit-like tool')
    parser.add_argument('--target', '-t', help='Host for Remote Connection', type=ascii)
    parser.add_argument('--port', '-p', help='Port for Remote Connection', type=int)
    parser.add_argument('--checksec', help='Enable checksec in script', action='store_true')
    parser.add_argument('--ssl', '-s', help='Enable SSL for Remote Connection', action='store_true')
    parser.add_argument('--local', help='Set script for local connection only', action='store_true')
    parser.add_argument('--remote', help='Set script for remote connection only', action='store_true')
    parser.add_argument('--no-script', help='Do not generate a script', action='store_true')
    parser.add_argument('--libc', help='Explicitely specify libc path to patch binary with', type=ascii)
    parser.add_argument('--interpreter', help='Explicitely specify linux interpreter path to patch binary with', type=ascii)
    parser.add_argument('--no-patching', help='Do not attempt to patch the binary', action='store_true')
    parser.add_argument('--output', '-o', help='Path to generated Script', default='./exploit.py')
    parser.add_argument('--binary', '-b', help='Path to binary')

    args = parser.parse_args()

    validate_args(args)

    if not args.binary:
        args.binary = getBinaryPath()
    
    if not args.no_patching:
        patch_binary(args)

    # Analyze binary
    elf = ELF(args.binary)
    context.binary = elf

    if not args.no_script:
        open(f'{args.output}', 'w').write(generateScript(args))
        os.chmod(args.output, 0o755)

if __name__ == '__main__':
    main()
