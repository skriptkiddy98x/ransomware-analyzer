"""End-to-end test of the behavioral observer using the BENIGN simulator.

No real malware is involved. The simulator only touches a temp sandbox dir.
"""

import os
import shutil
import tempfile
import time

from analyzer import behavioral, sim_sample


def _run(count=20):
    sandbox = os.path.join(tempfile.gettempdir(), "rz_pytest_sandbox")
    shutil.rmtree(sandbox, ignore_errors=True)
    os.makedirs(sandbox)
    sim_sample.seed_victim_files(sandbox, count)
    mon = behavioral.BehaviorMonitor([sandbox], poll_processes=False)
    mon.start()
    time.sleep(0.4)
    sim_sample.simulate(sandbox, count=count, seed=False)
    time.sleep(1.3)
    rep = mon.stop().to_dict()
    shutil.rmtree(sandbox, ignore_errors=True)
    return rep


def test_detects_mass_encryption():
    rep = _run(20)
    assert rep["encrypted_like_files"] >= 10
    assert "T1486" in rep["mitre_techniques"]
    assert rep["confidence"] >= 60
    assert "high confidence" in rep["verdict"]


def test_detects_locked_extension():
    rep = _run(20)
    assert ".locked" in rep["new_extensions"]
    assert rep["new_extensions"][".locked"] >= 10


def test_detects_ransom_note():
    rep = _run(20)
    assert any("DECRYPT" in os.path.basename(n).upper() for n in rep["ransom_notes"])
    titles = {f["title"] for f in rep["findings"]}
    assert "Ransom note dropped" in titles


def test_simulator_is_confined():
    """The simulator must refuse to run against the home directory."""
    import pytest
    with pytest.raises(RuntimeError):
        sim_sample.simulate(os.path.expanduser("~"))
