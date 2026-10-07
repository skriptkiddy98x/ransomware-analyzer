"""BENIGN ransomware-behavior simulator — FOR TESTING THE OBSERVER ONLY.

This is NOT malware. It is a harmless, self-contained test fixture that mimics
the *observable* behavior of ransomware strictly inside a sandbox directory you
pass in, so the behavioral observer can be tested without any real sample:

  * creates throwaway "victim" files,
  * "encrypts" them with a random keystream into high-entropy `.locked` copies
    and removes the originals (simulating the encrypt+rename pattern),
  * drops a ransom-note text file,
  * makes a best-effort DNS lookup to an obviously fake, non-routable domain.

Hard safety rules:
  * It only ever touches paths *inside* the sandbox directory you provide.
  * It refuses to run against a system/home directory.
"""

from __future__ import annotations

import os
import socket

RANSOM_NOTE = """!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

All your files have been encrypted. To recover them you must pay the ransom
in bitcoin. Do not turn off your computer.

How to decrypt:
  1. Download the Tor browser.
  2. Visit our site: http://exampledecrypt0000000000000000.onion
  3. Pay 0.05 BTC to bc1qexamplexampleexampleexampleexampl0000
  4. You will receive the decryption key.

This is a SIMULATION for security research. No real encryption or payment.
"""

VICTIM_SUBDIR = "victim_files"
NOTE_NAME = "READ_ME_TO_DECRYPT.txt"
LOCKED_EXT = ".locked"


def _guard(sandbox_dir: str) -> str:
    sb = os.path.abspath(sandbox_dir)
    home = os.path.abspath(os.path.expanduser("~"))
    forbidden = {home, os.path.abspath(os.sep)}
    if sb in forbidden or sb == os.path.abspath(os.getcwd()):
        raise RuntimeError("Refusing to simulate in a system/home/current directory. "
                           "Pass a dedicated empty sandbox directory.")
    os.makedirs(sb, exist_ok=True)
    return sb


def seed_victim_files(sandbox_dir: str, count: int = 20) -> list[str]:
    """Create harmless throwaway files to be 'encrypted' later."""
    sb = _guard(sandbox_dir)
    victims_dir = os.path.join(sb, VICTIM_SUBDIR)
    os.makedirs(victims_dir, exist_ok=True)
    paths = []
    for i in range(count):
        p = os.path.join(victims_dir, f"document_{i:03d}.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"Important document #{i}\n" + ("lorem ipsum dolor sit amet " * 40))
        paths.append(p)
    return paths


def simulate(sandbox_dir: str, count: int = 20, drop_note: bool = True,
             fake_network: bool = True, seed: bool = True) -> dict:
    """Run the benign simulation inside sandbox_dir. Returns a small summary."""
    sb = _guard(sandbox_dir)
    victims_dir = os.path.join(sb, VICTIM_SUBDIR)

    if seed:
        seed_victim_files(sb, count)

    encrypted = 0
    for root, _dirs, files in os.walk(victims_dir):
        for name in files:
            if name.endswith(LOCKED_EXT):
                continue
            src = os.path.join(root, name)
            try:
                with open(src, "rb") as f:
                    data = f.read()
                # one-time-pad-style XOR -> genuinely high-entropy output
                keystream = os.urandom(len(data)) if data else b""
                cipher = bytes(b ^ k for b, k in zip(data, keystream))
                with open(src + LOCKED_EXT, "wb") as f:
                    f.write(cipher)
                os.remove(src)
                encrypted += 1
            except OSError:
                pass

    note_path = None
    if drop_note:
        note_path = os.path.join(victims_dir, NOTE_NAME)
        with open(note_path, "w", encoding="utf-8") as f:
            f.write(RANSOM_NOTE)

    dns_attempted = None
    if fake_network:
        dns_attempted = "exampledecrypt-c2.invalid"
        try:
            socket.gethostbyname(dns_attempted)  # will fail (non-routable) — that's fine
        except Exception:
            pass

    return {
        "sandbox": sb,
        "encrypted_files": encrypted,
        "locked_extension": LOCKED_EXT,
        "note": note_path,
        "dns_attempted": dns_attempted,
    }


if __name__ == "__main__":
    import sys
    import tempfile
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        tempfile.gettempdir(), "ransim_sandbox")
    print("Simulating (benign) in:", target)
    print(simulate(target))
