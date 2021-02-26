# Green Pass - התו הירוק

Signature verification for the Green Pass (התו הירוק).

As (not really) specified in https://github.com/MohGovIL/Ramzor

## Verification Script

A pythonic implementation of the verification process can be found in [`verify.py`](verify.py).

Run the following command to install the dependency packages:
```bash
pip install -r requirements.txt
```

### Usage
Save your Green Pass as a `.png` file and execute:
```bash
python verify.py path_to_my_green_pass_image.png
```

## Verification Process Details

We describe in detail the signature verification steps using `openssl` commands.

### QR Code Data

Scan a Green Pass QR code, the encoded data has the following format:

```json
Base64EncodedSignature#{"id":"01/IL/ABCD1234ABCD1234ABCD1234ABCD1234#ABCD1234","et":1,"ct":1,"c":"IL MOH","cn":null,"fn":null,"g":null,"f":null,"gl":null,"fl":null,"idp":null,"idl":null,"b":"0001-01-01","e":"0001-01-01","a":"0001-01-01","p":[{"idl":"0123456789","e":"2021-01-01"}]}
```

Where `Base64EncodedSignature` are 256 bytes of an RSA signature signed with a 2048-bit public key and PKCS#1 v1.5 padding, followed by a `#` delimiter, and then the signed JSON payload as defined in https://github.com/MohGovIL/Ramzor#minimal-dataset

⚠️ **The current MOH implementation has a pitfall.** ⚠️ The JSON payload is not signed as is, but rather the **SHA256 hash** of the data is signed. This effectively means the payload is hashed twice, once manually, and once as part of the signature verification scheme.

### Certificates

The Ministry of Healthy RSA certificate seems to be available at https://ramzorfiles.z6.web.core.windows.net/RamzorQRPubKey.der

```bash
$ openssl x509 -pubkey -noout -inform der -in certs/RamzorQRPubKey.der -text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw4MJrQWgRnYakBsoU/eV
RxpvDnrGvtidQtfU0o0OGKU+p3H16ufPusBzKLHQPGAoZB33lU8wvfP01xUJTvod
qoi6KEKXGXC+XreQ1YJDKhIglYfPxJOOcauWf/tmV+w0xph6O3L5/2JrhxEjIbdu
E8zP8FvZ+KxVFA9LOFQzX7zbbiDUBLCRtIBhwtLCPIiy960O+lVZkMPXg5BrBWjc
NBrDN62PgOxGXvP3iF0bOlz1+m63q9cFzdKqVfOyl8jZRr3GzYD8SVSXO9EbfYId
8DEP+HMmqd4StD2X6OMDc9UrBBHx3nGbRpi2D9QuHA/kq/QAjQqnrd+iuzdSwQi+
mQIDAQAB
-----END PUBLIC KEY-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            09:77:f3:e6:67:08:85:38:25:c4:ad:f6:88:5a:02:8a
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert SHA2 Assured ID Code Signing CA
        Validity
            Not Before: Feb 19 00:00:00 2021 GMT
            Not After : Feb 27 23:59:59 2024 GMT
        Subject: C = IL, L = Jerusalem, O = Ministry of Health, CN = Ministry of Health
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c3:83:09:ad:05:a0:46:76:1a:90:1b:28:53:f7:
                    95:47:1a:6f:0e:7a:c6:be:d8:9d:42:d7:d4:d2:8d:
                    0e:18:a5:3e:a7:71:f5:ea:e7:cf:ba:c0:73:28:b1:
                    d0:3c:60:28:64:1d:f7:95:4f:30:bd:f3:f4:d7:15:
                    09:4e:fa:1d:aa:88:ba:28:42:97:19:70:be:5e:b7:
                    90:d5:82:43:2a:12:20:95:87:cf:c4:93:8e:71:ab:
                    96:7f:fb:66:57:ec:34:c6:98:7a:3b:72:f9:ff:62:
                    6b:87:11:23:21:b7:6e:13:cc:cf:f0:5b:d9:f8:ac:
                    55:14:0f:4b:38:54:33:5f:bc:db:6e:20:d4:04:b0:
                    91:b4:80:61:c2:d2:c2:3c:88:b2:f7:ad:0e:fa:55:
                    59:90:c3:d7:83:90:6b:05:68:dc:34:1a:c3:37:ad:
                    8f:80:ec:46:5e:f3:f7:88:5d:1b:3a:5c:f5:fa:6e:
                    b7:ab:d7:05:cd:d2:aa:55:f3:b2:97:c8:d9:46:bd:
                    c6:cd:80:fc:49:54:97:3b:d1:1b:7d:82:1d:f0:31:
                    0f:f8:73:26:a9:de:12:b4:3d:97:e8:e3:03:73:d5:
                    2b:04:11:f1:de:71:9b:46:98:b6:0f:d4:2e:1c:0f:
                    e4:ab:f4:00:8d:0a:a7:ad:df:a2:bb:37:52:c1:08:
                    be:99
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:5A:C4:B9:7B:2A:0A:A3:A5:EA:71:03:C0:60:F9:2D:F6:65:75:0E:58

            X509v3 Subject Key Identifier:
                87:3F:27:58:83:96:F0:67:2D:E5:E0:B5:9A:A7:B5:2A:50:A1:1E:A8
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 CRL Distribution Points:

                Full Name:
                  URI:http://crl3.digicert.com/sha2-assured-cs-g1.crl

                Full Name:
                  URI:http://crl4.digicert.com/sha2-assured-cs-g1.crl

            X509v3 Certificate Policies:
                Policy: 2.16.840.1.114412.3.1
                  CPS: http://www.digicert.com/CPS
                Policy: 2.23.140.1.4.1

            Authority Information Access:
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt

            X509v3 Basic Constraints: critical
                CA:FALSE
    Signature Algorithm: sha256WithRSAEncryption
         4a:44:6c:e6:24:56:69:72:54:59:d0:f0:29:5a:ca:89:38:71:
         68:56:6b:42:17:bd:ee:f4:e9:2c:7a:86:1d:4d:b7:f0:44:90:
         ec:fb:e9:38:0a:d7:72:38:5e:0b:3b:61:7d:96:36:b2:b4:44:
         b1:2e:fd:68:c2:8b:ec:12:66:37:06:81:bb:f5:bd:83:72:49:
         8c:e5:ec:53:56:d5:24:c1:35:56:d2:a3:8d:e1:a7:a0:69:ca:
         46:e3:f5:3b:dd:53:89:4a:27:ab:ee:94:bc:9e:46:60:b4:f8:
         f9:2a:88:87:fd:7d:46:6e:86:21:df:fe:56:d4:1c:61:6b:22:
         3c:ea:84:85:cd:fd:c6:f1:c6:e6:b9:5e:5c:df:23:da:e9:bc:
         6d:8a:bf:1c:c4:11:c1:26:c6:e6:84:21:6d:55:d6:63:c0:c3:
         dd:67:db:73:4b:ce:35:d7:72:0b:26:09:f3:20:1a:cf:6a:c1:
         98:b8:bc:48:3a:6f:a8:b1:89:35:55:85:2f:00:26:7d:9c:ee:
         46:b2:58:eb:9f:9d:4f:42:7e:03:52:24:27:88:50:dc:fc:c0:
         f2:48:ab:6b:2c:c7:0a:d0:c6:99:af:12:a5:3d:ea:dd:70:94:
         1c:fe:06:56:d9:b7:cf:b2:e7:7b:8b:13:d6:8b:1c:75:c6:6c:
         30:06:49:99
```

Convert the DER formatted certificate to a PEM file:

```bash
$ openssl x509 -pubkey -noout -inform der -in certs/RamzorQRPubKey.der > certs/RamzorQRPubKey.pem
```

Assumed the signed JSON data (without any trailing whitespace) is in `data.json`. Before we verify the data we need to hash the signed JSON:

```bash
$ openssl dgst -binary -sha256 data.json > data.hash
```

Assuming the Base64-decoded signature bytes are in `sig.bin` we can now run:

```bash
$ openssl dgst -verify certs/RamzorQRPubKey.pem -keyform PEM -sha256 -signature sig.bin data.hash
Verified OK
```

and receive successful verification.
