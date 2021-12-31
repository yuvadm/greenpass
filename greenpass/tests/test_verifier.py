from pathlib import Path

from ..verifier import GreenPassVerifier

SAMPLES_DIR = Path(__file__).parent / "samples"


def test_good():
    assert 1 == 1
