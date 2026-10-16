# asmPolicyDiff

Export all ASM policies from one or more BIG-IPs before and after an upgrade,
record the software version each time, and produce an HTML diff report.

## Setup
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt

## Usage
    ./asm_upgrade_diff.py export --phase pre  --host 10.1.1.245 -u admin
    # ... upgrade ...
    ./asm_upgrade_diff.py export --phase post --host 10.1.1.245 -u admin --noise-file noise-filter.txt
    ./asm_upgrade_diff.py report --noise-file noise-filter.txt

Multiple devices: `--hosts-file devices.txt` (see `devices.example.txt`).
Password: `-p`, `$BIGIP_PASSWORD`, or an interactive prompt.
Noise-filter rule syntax is documented at the top of `noise-filter.txt`.

Output goes to `./asm_snapshots/` (git-ignored): per-device pre/post exports,
`report.html`, `report.json`, and full `.diff` files.
