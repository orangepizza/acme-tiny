# -*- coding: utf-8 -*-
#
# TARGET arch is: []
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes
import os


def string_cast(char_pointer, encoding='utf-8', errors='strict'):
    value = ctypes.cast(char_pointer, ctypes.c_char_p).value
    if value is not None and encoding is not None:
        value = value.decode(encoding, errors=errors)
    return value


def char_pointer_cast(string, encoding='utf-8'):
    if encoding is not None:
        try:
            string = string.encode(encoding)
        except AttributeError:
            # In Python3, bytes has no encode attribute
            pass
    string = ctypes.c_char_p(string)
    return ctypes.cast(string, ctypes.POINTER(ctypes.c_char))

def ubyte_array_cast(inbytes):
    buffer = (ctypes.c_ubyte * len(bytes))(*inbytes)
    return buffer

def ubyte_ptr_to_bytes(ptr, len:int):
    return bytearray(ptr)

libname = "libed25519.so"
libpath = os.path.dirname(__file__) + os.path.sep + libname

_libraries = {}
_libraries['libed25519.so'] = ctypes.CDLL(libpath)
c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16


ed25519_create_seed = _libraries['libed25519.so'].ed25519_create_seed
ed25519_create_seed.restype = ctypes.c_int32
ed25519_create_seed.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
ed25519_create_keypair = _libraries['libed25519.so'].ed25519_create_keypair
ed25519_create_keypair.restype = None
ed25519_create_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
size_t = ctypes.c_uint64
ed25519_sign = _libraries['libed25519.so'].ed25519_sign
ed25519_sign.restype = None
ed25519_sign.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
ed25519_verify = _libraries['libed25519.so'].ed25519_verify
ed25519_verify.restype = ctypes.c_int32
ed25519_verify.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), size_t, ctypes.POINTER(ctypes.c_ubyte)]
ed25519_add_scalar = _libraries['libed25519.so'].ed25519_add_scalar
ed25519_add_scalar.restype = None
ed25519_add_scalar.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
ed25519_key_exchange = _libraries['libed25519.so'].ed25519_key_exchange
ed25519_key_exchange.restype = None
ed25519_key_exchange.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
__all__ = \
    ['ed25519_add_scalar', 'ed25519_create_keypair',
    'ed25519_create_seed', 'ed25519_key_exchange', 'ed25519_sign',
    'ed25519_verify', 'size_t']




def sign(message:bytes, publickey:bytes, privatekey:bytes):
    pysig = bytearray(64)
    csig = (ctypes.c_ubyte * 64).from_buffer(pysig)
    cmessage  = (ctypes.c_ubyte * len(message)).from_buffer_copy(message)
    cpub = (ctypes.c_ubyte * 32).from_buffer_copy(publickey)
    cpriv = (ctypes.c_ubyte * 64).from_buffer_copy(privatekey)
    ed25519_sign(csig, cmessage, size_t(len(message)), cpub, cpriv)
    return pysig
