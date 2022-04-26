import base64
import cryptography.x509
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
import cryptography.utils, cryptography.hazmat.primitives.asymmetric

CSRBYTE = b"""-----BEGIN CERTIFICATE REQUEST-----
MIIBDzCBwgIBADAAMCowBQYDK2VwAyEAAJhHmOIxin7dZvKd6aiZGCNrl2ngSbR1
1Ei727ydOEaggY4wFAYEZ4EMKjEMBAosNiTQxXU35ZAqMBoGBGeBDCkxEgQQYpVw
QRzcyq72eWGTw8flMjBaBgkqhkiG9w0BCQ4xTTBLMEkGA1UdEQRCMECCPmFjbWVw
Z2hjZ2dmaDV4bGc2a282dGtlemRhcnd4ZjNqNGJlM2k1b3VqYzU1eHBlNWhiZGph
dXFkLm9uaW9uMAUGAytlcANBACfTi2BHuRhWP+UHJ75zz/Vh2HNj7A97Jeq/JDyN
EMSC/YZWhP+vFEdveAzWgi3IBDNCkJpp09HbDhyJNgfNvw8=
-----END CERTIFICATE REQUEST-----
"""
TESTCSR = b"""-----BEGIN CERTIFICATE REQUEST-----
MIIBAzCBtgIBADAnMQswCQYDVQQGEwJERTEYMBYGA1UEAwwPd3d3LmV4YW1wbGUu
Y29tMCowBQYDK2VwAyEAK87g0b8CC1eA5mvKXt9uezZwJYWEyg74Y0xTZEkqCcyg
XDBaBgkqhkiG9w0BCQ4xTTBLMAsGA1UdDwQEAwIEMDATBgNVHSUEDDAKBggrBgEF
BQcDATAnBgNVHREEIDAegg93d3cuZXhhbXBsZS5jb22CC2V4YW1wbGUuY29tMAUG
AytlcANBAHSBX9+RjKgO3MjD72nHdiqmPdotBqF2+0mMxQB2sB3Z9WOCF1M+UvFd
JyTsMetxAQZ2UEYMCqo84oG2CWn6gAY=
-----END CERTIFICATE REQUEST-----
"""

def OnionNameFromPubkeyByte(publickeybytes :bytes) -> str:
    """Create onion domain name from ed25519 private key"""
    work= hashes.Hash(hashes.SHA3_256())
    work.update(b".onion checksum")
    work.update(publickeybytes)
    work.update(b"\x03")
    hashtank = work.finalize()
    addr = base64.b32encode(hashtank).decode()
    addr = addr + ".onion"
    return addr


csr = cryptography.x509.load_pem_x509_csr(CSRBYTE)
print(csr.is_signature_valid, "\n")
print(csr.extensions)

pubkey = csr.public_key()
pubbyte = pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print(pubbyte)
print(OnionNameFromPubkeyByte(pubbyte))

