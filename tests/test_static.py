"""Unit tests for the static analyzer. Uses generated benign fixtures only."""

import os

from analyzer import static


def test_entropy_bounds():
    assert static._shannon_entropy(b"") == 0.0
    assert static._shannon_entropy(b"\x00" * 1000) == 0.0
    high = static._shannon_entropy(os.urandom(4096))
    assert high > 7.5  # random data ~ 8.0


def test_hashes(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello world")
    h = static.file_hashes(str(p))
    assert h["sha256"] == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    assert set(h) == {"md5", "sha1", "sha256"}


def test_ioc_extraction():
    strings = [
        "visit http://evil.example.com/pay now",
        "contact attacker@mail.tld",
        "btc bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "server 185.12.34.56 online",
        "mirror http://abcdefghij234567.onion/",
    ]
    iocs = static.extract_iocs(strings)
    assert any("evil.example.com" in u for u in iocs.get("urls", []))
    assert "185.12.34.56" in iocs.get("ipv4", [])
    assert iocs.get("onion")
    assert iocs.get("bitcoin")
    assert iocs.get("emails")


def test_ransom_note_regex():
    assert static.RANSOM_NOTE_HINTS.search("All your files are encrypted")
    assert static.RANSOM_NOTE_HINTS.search("How to decrypt your data")
    assert not static.RANSOM_NOTE_HINTS.search("just a normal sentence about cats")


def test_analyze_text_file(tmp_path):
    p = tmp_path / "note.txt"
    p.write_text("Your files have been encrypted. Pay the ransom in bitcoin. "
                 "Visit http://abcdefghij234567.onion to decrypt.")
    rep = static.analyze(str(p)).to_dict()
    assert rep["is_pe"] is False
    assert rep["ransom_note_strings"]
    assert rep["suspicious_score"] > 0


def test_analyze_real_pe_if_available():
    """If a system PE exists, parsing must succeed and find imports."""
    candidates = [r"C:\Windows\System32\notepad.exe",
                  r"C:\Windows\System32\calc.exe"]
    target = next((c for c in candidates if os.path.exists(c)), None)
    if not target:
        return  # not on Windows / not available -> skip
    rep = static.analyze(target).to_dict()
    assert rep["is_pe"] is True
    assert rep["pe_info"]["import_count"] >= 1
