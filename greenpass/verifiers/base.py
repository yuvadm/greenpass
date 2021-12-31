class Verifier(object):
    def __init__(self, data):
        self.data = data

    def verify(self):
        raise NotImplementedError()

    def get_cert_path(self, name):
        return Path(__file__).absolute().parent / "certs" / name
