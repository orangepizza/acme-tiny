"""functions need to handle .onion address in acme context"""
import base64
import os
import hashlib
from ed25519 import ed25519 as ced25519
import cryptography.x509 as pyx509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.name import _ASN1Type
# csr crafting
from cryptography.x509.oid import NameOID


def ReadOnionSite(onionsitefolder="/var/lib/tor/hidden_service"):
    """
    read config files from tor config site, default path is where debian tor package used
    Problem: tor saves private key that normal ed25519 impli doesn't like
    """

    with open(os.path.join(onionsitefolder, "hs_ed25519_secret_key"), "rb") as f:
        keyfile = f.read()
        skeybytes = keyfile[32:]
    with open(os.path.join(onionsitefolder, "hs_ed25519_public_key"), "rb") as f:
        keyfile = f.read()
        pkeybytes = keyfile[32:]
    with open(os.path.join(onionsitefolder, "hostname"), "r", encoding="utf-8") as f:
        onionname = f.read()
        onionname = onionname.strip()
    return onionname, skeybytes, pkeybytes


def CraftCSRwithTorkey(name, privkey: bytes, publickey: bytes, nonce: bytes):
    # openssh doesn't like our private key format, so we do
    tmpkey = ed25519.Ed25519PrivateKey.from_private_bytes(b"0"*32)
    tmppub = tmpkey.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
        )
    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(publickey)
    derpub = pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
        )
    tmpcsr = CraftOnionChallangeCSR(name, tmpkey, nonce)
    csrbyte = tmpcsr.public_bytes(serialization.Encoding.DER)
    tbsbyte = tmpcsr.tbs_certrequest_bytes

    # sanity check
    keyname = OnionNameFromPubkey(pubkey)
    if name != keyname:
        print("onion name didn't match publickey given")
    # replace temp key in csr to real key and sig
    # we can just byte replace them this because it's same length
    tbsbyte = tbsbyte.replace(tmppub, derpub)
    realsig = ced25519.sign(tbsbyte, publickey, privkey)
    csrbyte = csrbyte.replace(tmppub, derpub)
    csrbyte = csrbyte.replace(tmpcsr.signature, realsig)
    csr = pyx509.load_der_x509_csr(csrbyte)
    csrbyte = csr.public_bytes(serialization.Encoding.DER)
    return csrbyte


def CraftOnionChallangeCSR(name, privkey: ed25519.Ed25519PrivateKey, nonce: bytes):
    """
    Create onionchallange CSR from onion key, expects cryptgraphy ed25519 private key(seed).
    tor's expended private key cannot converted back to seed, call CraftCSRwithTorkey instead.
    """
    CA_NONCE_OID = "2.23.140.41"
    APPLI_NONCE_OID = "2.23.140.42"
    # load templetecsm
    # although CA shouldn't care about names in this csr,
    # pyca will error if csr have no name in it
    # todo: get at way to handle hs_onion format
    # this only accepts bytes form of ed25519 keys
    builder = pyx509.CertificateSigningRequestBuilder()
    # this needs cryptography 37.0 to be work, not released yet
    builder = builder.add_attribute(
        pyx509.ObjectIdentifier(CA_NONCE_OID),
        nonce,
        _tag=_ASN1Type.OctetString
        )
    builder = builder.add_attribute(
        pyx509.ObjectIdentifier(APPLI_NONCE_OID),
        os.urandom(16),
        _tag=_ASN1Type.OctetString
        )
    builder = builder.subject_name(pyx509.Name([
        pyx509.NameAttribute(NameOID.COMMON_NAME, name)
    ]))
    builder = builder.add_extension(
        pyx509.SubjectAlternativeName(
            [pyx509.DNSName(name)]
        ),
        critical=False
    )
    csr = builder.sign(privkey, None)
    return csr


def OnionNameFromPubkey(key, suffix=True):
    """
    copyed from stem.hidden_service address_from_identity_key
    Converts a hidden service identity key into its address. This accepts all
    key formats (private, public, or public bytes).

    :param Ed25519PublicKey,Ed25519PrivateKey,bytes key: hidden service identity key
    :param bool suffix: includes the '.onion' suffix if true, excluded otherwise

    :returns: **unicode** hidden service address

    """
    if not isinstance(key, bytes):
        key = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)  # normalize key into bytes

    version = bytes([3, ])
    checksum = hashlib.sha3_256(b'.onion checksum' + key + version).digest()[:2]
    onion_address = base64.b32encode(key + checksum + version)

    return (onion_address + b'.onion' if suffix else onion_address).decode('utf-8', 'replace').lower()

newkey = ed25519.Ed25519PrivateKey.generate()
tpk, tsk = ced25519.create_keypair(newkey.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw, serialization.NoEncryption()))
name = OnionNameFromPubkey(newkey.public_key())
testcsr = CraftCSRwithTorkey(name, bytes(tsk), bytes(tpk), b"AAAAAAAAAAAAAAAAAAAAAA")

