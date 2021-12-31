from pathlib import Path

from ..verifier import GreenPassVerifier

SAMPLES_DIR = Path(__file__).parent / "samples"


def test_ramzor_samples():
    v = GreenPassVerifier.from_pdf(str(SAMPLES_DIR / "CovidCertificate_01.pdf"))
    assert v.verify() is True
