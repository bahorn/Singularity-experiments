"""
Script to replace the export symnames with null bytes, so it will not show in
/proc/kallsyms.

doesn't directly modify symtab, just strtab.

might miss things in a few edge cases
"""
import sys
import subprocess

def run_command(command):
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        capture_output=True,
        text=True
    )
    return result.stdout, result.stderr

fname = sys.argv[1]

cmd_out, _ = run_command(
    f'readelf -W -T --syms {fname} | grep -e "FUNC" -e "OBJECT"'
)

all_syms = []

for line in cmd_out.split('\n'):
    sym = line.split(' ')[-1]
    if not sym:
        continue
    all_syms.append(f'{sym}')

print(all_syms)

with open(fname, 'rb') as f:
    to_patch = bytearray(f.read())

cmd_out, _ = run_command(
    f'readelf -S -W {fname} | grep "\\.strtab" | awk \'{{print "0x"$5 " 0x"$6}}\''
)
a, b = cmd_out.strip(). split(' ')
symtab_start = int(a, 16)
symtab_end = symtab_start + int(b, 16)

to_modify = to_patch[symtab_start:symtab_end]

def find_all(data, pattern):
    positions = []
    start = 0
    
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        positions.append((pos, len(pattern)))
        start = pos + 1
    
    return positions

all_pos = []
for sym in all_syms:
    all_pos += find_all(to_modify, b'\x00' + bytes(sym, 'ascii') + b'\x00')

for pos, sze in all_pos:
    to_modify[pos:pos+sze] = b'\x00' * sze

with open(fname, 'wb') as f:
    to_patch[symtab_start:symtab_end] = to_modify
    f.write(to_patch)
