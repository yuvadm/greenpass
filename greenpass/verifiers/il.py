from .base import Verifier


class IsraeliVerifier(Verifier):
    def validate(self):
        if not self.data.decode().startswith("GreenPass"):
            raise Exception("Green pass QR code contains no signature to verify")

    def verify(self):
        return False
