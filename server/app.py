from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import traceback
import logging
from flask import Flask
app = Flask(__name__)

logging.basicConfig(filename='server.log', level=logging.INFO)

BLOCK_SZ = 16 # bytes
key = b"Z\xb9\xc1\\\r.\xd6`'{]\x05\x9d\xac\x96\xff"
iv = bytes.fromhex("00112233445566778899aabbccddeeff")
encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=iv).encrypt

class PadError(Exception):
    pass

def pad(m:bytes)->bytes:
    pad_len = BLOCK_SZ - len(m) % BLOCK_SZ
    return m + bytes([pad_len] * pad_len)

def unpad(m:bytes)->bytes:
    # logging.info(f"[unpadding:{m}]")
    pad_len = m[-1]
    if pad_len > 16:
        raise PadError()
    for p in m[-pad_len:]:
        if p != pad_len:
            raise PadError()
    return m[:-pad_len]

@app.route('/oracle/<c>')
def orcale(c:str):
    ct = bytes.fromhex(c)
    decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=ct[:BLOCK_SZ]).decrypt
    try:
        logging.info(unpad(decrypt(ct[BLOCK_SZ:])))
        return "valid"
    except PadError:
        return "invalid"


@app.route('/ctx')
def ctx_provider():
    return (iv+encrypt(pad(open("flag.txt", "r").read().encode()))).hex()
