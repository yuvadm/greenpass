import base64
import click
import fitz
import json

from io import BytesIO
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from PIL import Image
from pyzbar import pyzbar


class GreenPassVerifier(object):
    def __init__(self, data_bytes):
        sig, self.payload = data_bytes.split(b"#", maxsplit=1)
        self.signature = base64.decodebytes(sig)
        self.data = json.loads(self.payload)

        self.validate_data()
        self.details = self.get_details()
        self.digest = self.get_digest()

        self.cert = self.get_cert_path("RamzorQRPubKey.pem")

    @classmethod
    def from_payload(cls, path):
        with open(path, "rb") as f:
            return cls(f.read().strip())

    @classmethod
    def from_qr(cls, path):
        return cls(pyzbar.decode(Image.open(path))[0].data)

    @classmethod
    def from_pdf(cls, path):
        doc = fitz.open(path)
        for i in range(len(doc)):
            for img in doc.get_page_images(i):
                xref, width = img[0], img[2]
                if width in (
                    3720,  # in green pass
                    4200,  # in vaccination certificate
                ):
                    img = fitz.Pixmap(doc, xref)
                    data = img.getImageData(output="png")
                    return cls.from_qr(BytesIO(data))

    def validate_data(self):
        ct = self.data["ct"]
        if ct not in (1, 2):
            click.secho(f"Unknown certificate type ct={ct}", fg="red", bold=True)
            click.get_current_context().exit()

    def get_cert_path(self, name):
        return Path(__file__).absolute().parent / "certs" / name

    def get_details(self):
        details = []
        data = self.data
        if data["ct"] == 1:
            for i in range(len(data["p"])):
                details.append(
                    {
                        "id_num": data["p"][i]["idl"],
                        "valid_by": data["p"][i]["e"],
                        "cert_id": data["id"],
                    }
                )
        elif data["ct"] == 2:
            details.append(
                {
                    "id_num": data["idl"],
                    "valid_by": data["e"],
                    "cert_id": data["id"],
                }
            )
        return details

    def get_digest(self):
        ct = self.data["ct"]
        if ct == 1:
            digest = self.payload.decode().encode("utf8")
        elif ct == 2:
            h = hashes.Hash(hashes.SHA256())
            h.update(self.payload)
            digest = h.finalize()
        return digest

    def verify(self):
        for d in self.details:
            click.echo(f"\tIsraeli ID Number {d['id_num']}")
            click.echo(f"\tID valid by {d['valid_by']}")
            click.echo(f"\tCert Unique ID {d['cert_id']}")

        with open(self.cert, "rb") as f:
            k = serialization.load_pem_public_key(f.read())
            try:
                k.verify(
                    self.signature,
                    self.digest,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                click.secho("Valid signature!", fg="green", bold=True)
            except InvalidSignature:
                click.secho("Invalid signature!", fg="red", bold=True)


@click.command()
@click.option("-p", "--pdf-path", type=click.Path(exists=True), help="Path to PDF file")
@click.option(
    "-i",
    "--image-path",
    type=click.Path(exists=True),
    help="Path to an image with the QR code",
)
@click.option(
    "-t",
    "--txt-path",
    type=click.Path(exists=True),
    help="Path to decoded QR code textual content",
)
def verify_cmd(pdf_path="", image_path="", txt_path=""):
    if image_path:
        verifier = GreenPassVerifier.from_qr(image_path)
    elif pdf_path:
        verifier = GreenPassVerifier.from_pdf(pdf_path)
    elif txt_path:
        verifier = GreenPassVerifier.from_payload(txt_path)
    else:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.exit()

    verifier.verify()


if __name__ == "__main__":
    verify_cmd()
