import click

from .verifier import GreenPassVerifier


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
def verify(pdf_path="", image_path="", txt_path=""):
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

    valid = verifier.verify()
    if valid:
        click.secho("✅ Valid signature!", fg="green", bold=True)
    else:
        click.secho("❌ Invalid signature!", fg="red", bold=True)
