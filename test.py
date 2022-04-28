import base64
import cryptography.x509
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
import cryptography.utils, cryptography.hazmat.primitives.asymmetric

from onion import OnionNameFromPubkey


def TestNameGen():
    CSRBYTE = b"""-----BEGIN CERTIFICATE REQUEST-----
    MIIBDzCBwgIBADAAMCowBQYDK2VwAyEAAJhHmOIxin7dZvKd6aiZGCNrl2ngSbR1
    1Ei727ydOEaggY4wFAYEZ4EMKjEMBAosNiTQxXU35ZAqMBoGBGeBDCkxEgQQYpVw
    QRzcyq72eWGTw8flMjBaBgkqhkiG9w0BCQ4xTTBLMEkGA1UdEQRCMECCPmFjbWVw
    Z2hjZ2dmaDV4bGc2a282dGtlemRhcnd4ZjNqNGJlM2k1b3VqYzU1eHBlNWhiZGph
    dXFkLm9uaW9uMAUGAytlcANBACfTi2BHuRhWP+UHJ75zz/Vh2HNj7A97Jeq/JDyN
    EMSC/YZWhP+vFEdveAzWgi3IBDNCkJpp09HbDhyJNgfNvw8=
    -----END CERTIFICATE REQUEST-----
    """


    csr = cryptography.x509.load_pem_x509_csr(CSRBYTE)
    print(csr.is_signature_valid, "\n")
    print(csr.extensions)

    pubkey = csr.public_key()
    pubbyte = pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print(pubbyte, len(pubbyte))
    print(OnionNameFromPubkey(pubbyte))
    assert (OnionNameFromPubkey(pubbyte) 
    == "acmepghcggfh5xlg6ko6tkezdarwxf3j4be3i5oujc55xpe5hbdjauqd.onion")
