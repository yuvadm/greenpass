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


def cert(name):
    return Path(__file__).absolute().parent / "certs" / name


def verify(qr_code_bytes):
    b64, payload = qr_code_bytes.split(b"#", maxsplit=1)
    sig = base64.decodebytes(b64)

    data = json.loads(payload)
    payload = payload.decode().encode("utf8")

    details = []

    if data["ct"] == 1:
        digest = payload
        for i in range(len(data["p"])):
            details.append(
                {
                    "id_num": data["p"][i]["idl"],
                    "valid_by": data["p"][i]["e"],
                    "cert_id": data["id"],
                }
            )
    elif data["ct"] == 2:
        h = hashes.Hash(hashes.SHA256())
        h.update(payload)
        digest = h.finalize()
        details.append(
            {
                "id_num": data["idl"],
                "valid_by": data["e"],
                "cert_id": data["id"],
            }
        )

    else:
        click.secho("Unsupported certificate type", fg="red")
        return

    for d in details:
        click.echo(f"\tIsraeli ID Number {d['id_num']}")
        click.echo(f"\tID valid by {d['valid_by']}")
        click.echo(f"\tCert Unique ID {d['cert_id']}")

    with open(cert("RamzorQRPubKey.pem"), "rb") as f:
        k = serialization.load_pem_public_key(f.read())
        try:
            k.verify(
                sig,
                digest,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            click.secho("Valid signature!", fg="green", bold=True)
        except InvalidSignature:
            click.secho("Invalid signature!", fg="red", bold=True)


def read_qr_code(image_path):
    return pyzbar.decode(Image.open(image_path))[0].data


def read_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    for i in range(len(doc)):
        for img in doc.get_page_images(i):
            xref, width = img[0], img[2]
            if width in (
                3720,  # in green pass
                4200,  # in vaccination certificate
            ):
                img = fitz.Pixmap(doc, xref)
                data = img.getImageData(output="png")
                return read_qr_code(BytesIO(data))


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
        verify(read_qr_code(image_path))
    elif pdf_path:
        verify(read_pdf(pdf_path))
    elif txt_path:
        with open(txt_path, "rb") as f:
            verify(f.read().strip())
    else:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.exit()


if __name__ == "__main__":
    verify_cmd()
