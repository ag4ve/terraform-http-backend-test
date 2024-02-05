#!/usr/bin/env python

import magic
from pathlib import Path
from OpenSSL import crypto
from typing import Any
from datetime import timedelta

class Cert:
    def __init__(self) -> None:
        self.key: crypto.PKey = self.create_key()
        self.cert: crypto.X509 = self.create_cert(self.key)
        self.csr: crypto.X509Req = self.create_csr(self.key)
        self.TYPE_RSA: int = crypto.TYPE_RSA
        self.FILETYPE_PEM: int = crypto.FILETYPE_PEM

    def is_pem_file(filename: str) -> bool:
        """
        Check if a file is a PEM certificate.
        filename: str
        """
        file = Path(filename)
        if file.exists():
            if file.is_symlink():
                tmpfile = file
                file = tmpfile.resolve()

            if magic.from_file(file) == "PEM certificate":
                return True

    def create_key(self, bits: int = 2048) -> crypto.PKey:
        """
        Create a private key.
        bits: int
        """
        key = crypto.PKey()
        key.generate_key(self.TYPE_RSA, bits)
        return key

    def create_csr(self, key: crypto.PKey = self.key, algo: str = 'sha256', cn: str = "localhost") -> crypto.X509Req:
        """
        Create a certificate signing request.
        key: crypto.PKey
        algo: str
        cn: str
        """
        if key is None:
            key = self.create_key()
        csr = crypto.X509Req()
        csr.get_subject().CN = cn
        csr.set_pubkey(key)
        csr.sign(key, algo)
        return csr

    def create_cert(self, key: crypto.PKey = self.key, csr: crypto.X509Req = self.csr, algo: str = 'sha256', years: int = 10, cn: str = "localhost") -> crypto.X509:
        """
        Create a self-signed certificate.
        key: crypto.PKey
        csr: crypto.X509Req
        algo: str
        years: int
        cn: str
        """
        if key is None:
            key = self.create_key()
        cert = crypto.X509()
        if csr is None:
            cert.get_subject().CN = cn
            cert.set_pubkey(key)
        else:
            cert.set_subject(csr.get_subject())
            cert.set_pubkey(csr.get_pubkey())
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(timedelta(days=years*365.25).total_seconds())
        cert.set_issuer(cert.get_subject())
        cert.sign(key, algo)
        return cert

    def save(self, filename: str, target: str = "key") -> None:
        """
        Save a certificate of type target to a file.
        filename: str
        target: str
        """
        string = ""
        if target == "key":
            string = crypto.dump_privatekey(self.FILETYPE_PEM, self.key).decode("utf-8")
        elif target == "cert":
            string = crypto.dump_certificate(self.FILETYPE_PEM, self.cert).decode("utf-8")
        elif target == "csr":
            string = crypto.dump_certificate_request(self.FILETYPE_PEM, self.create_csr()).decode("utf-8")

        with open(filename, "wt") as f:
            f.write(string)
