# Isolated analysis lab — setup guide

Detonating real ransomware is dangerous. Follow this before running the
`detonate`/`monitor` commands with a real sample. If anything here is unclear,
stick to `python rza.py static` and the `simulate` self-test, which never execute
a real sample.

## 1. A dedicated analysis VM

- Install **VirtualBox** and create a **Windows 10/11 VM** (most ransomware targets
  Windows). For Linux samples, use a Linux VM instead.
- Install your analysis tooling inside the VM: Python + this repo, **Sysmon**
  (Sysinternals) with a good config (e.g. SwiftOnSecurity's), and optionally
  Process Monitor / Process Hacker / Wireshark.
- Take a **clean snapshot** named e.g. `clean`. **Revert to it after every run.**

## 2. Network isolation

Pick one:

- **No network** (simplest): set the VM network adapter to *Not attached*.
- **Host-only** + a **fake internet**: a second VM running **INetSim** or
  **FakeNet-NG** as the gateway, so the sample "talks" to a simulated internet and
  you capture C2 attempts without touching the real one.

**Never** use NAT/bridged to the live internet while detonating.

## 3. Close the escape hatches

In the VM settings, **disable**:

- Shared folders
- Shared clipboard (set to *Disabled*)
- Drag-and-drop (set to *Disabled*)

Move samples in before detonation via an ISO you mount read-only, or download them
inside the VM. Keep them in a **password-protected zip** until you detonate.

## 4. Host hygiene

- Keep **VirtualBox updated** (there have been VM-escape CVEs).
- Do **not** store sensitive data on the host used for analysis; ideally use a
  dedicated/old machine.
- Assume malware may detect the VM (anti-VM/anti-sandbox) and change behavior.

## 5. Getting samples responsibly

Use reputable research sources and handle with care:

- **MalwareBazaar** (abuse.ch)
- **VX-Underground**
- **theZoo**

Only analyze samples you are legally authorized to handle.

## 6. A typical run

```bash
# inside the VM, with Sysmon installed and a clean snapshot taken:
python rza.py static sample.exe --out reports            # safe first pass
python rza.py detonate sample.exe --yes-run-in-vm --timeout 120 --out reports
# then: read reports/sample.exe.html, export IOCs, and REVERT the snapshot
```
