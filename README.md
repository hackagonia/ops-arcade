# Ops-Arcade

> A personal arsenal of BOFs, Aggressor scripts, automation tooling, and red team utilities -- built in the field, sharpened for real engagements.

**Everything here is for authorized operations only. No exceptions.**

---

## What's Inside

```
Ops-Arcade/
├── BOFs/
│   ├── situational-awareness/     # Know your environment before you move
│   ├── privilege-escalation/      # Find the cracks, widen them
│   ├── defense-evasion/           # See what's watching, work around it
│   └── lateral-movement/          # Get across the wire quietly
│
├── aggressor/
│   ├── recon/                     # Auto-recon on check-in, less clicking
│   ├── post-ex/                   # Chained post-ex workflows
│   └── utils/                     # Operator QoL -- logging, tagging, menus
│
├── automation/
│   ├── python/                    # Parsing, scoping, reporting
│   └── bash/                      # Wrappers and pipeline helpers
│
├── tools/                         # Everything else that doesn't fit a box
│
└── resources/                     # Notes, cheat sheets, reference material
```

---

## Tools Index

### BOFs

| Name | Category | Description |
|------|----------|-------------|
| `env_hunt` | Situational Awareness | Enumerate environment variables across remote processes |
| `pipe_enum` | Situational Awareness | Named pipe enumeration with ACL output |
| `token_info` | Situational Awareness | Detailed token privilege and group breakdown |
| `lsa_sessions` | Situational Awareness | LSA logon session query -- no LSASS handle required |
| `svc_perms` | Privilege Escalation | Service binary ACL and unquoted path hunting |
| `amsi_check` | Defense Evasion | AMSI provider registration and patch state inspection |

| Tool | Description |
|-----|-------------|
| `` |  |
| `` |  |
| `` |  |
| `` |  |
| `` |  |
| `` |  |


### BOFs
| Name | Category | Description |
|------|----------|-------------|
|`whoami`| Situational Awareness | Complete rewrite using direct PEB/TEB reads instead of token queries. Extracts username, domain, computer name, OS version, architecture, PID, PPID, session ID, debug detection. Zero security-relevant API calls.|
|`env`| Situational Awareness | Replaces GetEnvironmentStrings with direct PEB→ProcessParameters→Environment memory walk. Enumerates all environment variables via pure pointer arithmetic on the environment block. No API calls whatsoever.|
|`listmods`| Situational Awareness | Replaces CreateToolhelp32Snapshot/EnumProcessModules with PEB→Ldr→InMemoryOrderModuleList walk. Shows base address, image size, full path, and flags known security/analysis DLLs (AMSI, Defender, .NET, debug helpers, sandbox/AV products). Zero API calls.|
|`netstat`| Situational Awareness | Uses GetExtendedTcpTable/GetExtendedUdpTable for PID-aware connection tables (single call each vs per-entry approach). PID-to-process-name resolution via NtQuerySystemInformation instead of per-process OpenProcess. Inline byte-swap macro eliminates WS2_32 dependency entirely.|
|`sc_enum`| Situational Awareness | Replaces OpenSCManager/EnumServicesStatus/QueryServiceConfig with direct NT registry walk (NtOpenKey/NtEnumerateKey/NtQueryValueKey on HKLM\SYSTEM\CurrentControlSet\Services). Produces combined sc query + sc qc output per service including type, start mode, error control, binary path, dependencies (REG_MULTI_SZ), logon account, description, failure command, and inferred running state via process-name matching against NtQuerySystemInformation. Bypasses SCM entirely.|
|`tasklist`| Situational Awareness | Replaces WMI/COM and CreateToolhelp32Snapshot with a single NtQuerySystemInformation(SystemProcessInformation) call. Displays PID, PPID, thread count, handle count, working set, session ID, and process name. No per-process OpenProcess calls needed.|



*Index updated as tools are added. Each BOF directory contains its own README.md with full argument reference and example output.*

### Aggressor Scripts

| Script | Description |
|--------|-------------|
| `auto_recon.cna` | Fires recon BOF chain on new Beacon check-in |
| `post_ex_menu.cna` | Right-click menu for common post-ex actions |
| `beacon_logger.cna` | Structured logging of all Beacon output to disk |
| `scope_guard.cna` | Warns operator before tasking out-of-scope hosts |

### Automation

| Script | Lang | Description |
|--------|------|-------------|
| `parse_beacon_output.py` | Python | Normalize and parse raw Beacon logs |
| `scope_checker.py` | Python | Validate targets against engagement scope file |
| `cs_log_exporter.py` | Python | Export CS logs to JSON/CSV for reporting |
| `recon_wrap.sh` | Bash | Single-command recon pipeline wrapper |

---

## Building BOFs

### Requirements

```bash
# Debian/Ubuntu
sudo apt install mingw-w64 make

# Arch
sudo pacman -S mingw-w64-gcc make
```

### Build Everything

```bash
cd BOFs/
make all
```

### Build One BOF

```bash
cd BOFs/<category>/<bof_name>/
make
```

Output lands next to the source as `<bof_name>.x64.o`.

---

## Usage

### Load All Scripts in Cobalt Strike

```
Script Manager -> Load -> Ops-Arcade/aggressor/load_all.cna
```

Or load individual .cna files a la carte.

### Run a BOF

```
beacon> inline-execute BOFs/<category>/<bof_name>/<bof_name>.x64.o [args]
```

### Example -- pipe_enum

```
beacon> inline-execute BOFs/situational-awareness/pipe_enum/pipe_enum.x64.o
[*] Enumerating named pipes...
[+] \pipe\lsass          RW: SYSTEM, Administrators
[+] \pipe\svcctl         RW: SYSTEM
[+] \pipe\spoolss        RW: Everyone  <-- worth a look
[*] Done.
```

### Example -- svc_perms

```
beacon> inline-execute BOFs/privilege-escalation/svc_perms/svc_perms.x64.o
[*] Scanning service binaries for weak permissions...
[!] C:\Program Files\VulnApp\service.exe  -- Writable by: BUILTIN\Users
[!] C:\Unquoted Path\Service Here\bin.exe -- Unquoted, spaces in path
[*] Done. 2 finding(s).
```

---

## Contributing

If you're adding a tool, follow the structure:

```
BOFs/<category>/<tool_name>/
├── <tool_name>.c
├── <tool_name>.cna
└── README.md
```

Every tool needs a README.md with at minimum: **purpose**, **arguments**, and **example output**. No undocumented drops.

For Python/Bash tools, include a docstring or header block with usage. Keep dependencies minimal -- operators shouldn't have to fight their own tooling on an engagement.

Pull requests welcome. Keep it clean, keep it documented.

---

## Credits

- **TrustedSec** -- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) -- foundational BOF patterns and philosophy this project builds on

---

## Legal

This toolkit is provided strictly for **authorized penetration testing and red team engagements**. You are responsible for obtaining proper written authorization before using any tool in this repository against any system or network.

Unauthorized use is illegal. The author assumes zero liability for misuse.

If you're using this without a signed SOW, you're on your own.

---

*Built for operators. Use responsibly.*
