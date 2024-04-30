from os import urandom
import cryptography
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SGX_RSA_PUBLIC_EXPONENT = 3
SGX_RSA_KEY_SIZE = 3072
data = b'dupa'

def sign_with_private_key(data, private_key):
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return signature, int.from_bytes(signature, byteorder='big')

while True:
    print('.', end='', flush=True)
    key = rsa.generate_private_key(public_exponent=SGX_RSA_PUBLIC_EXPONENT,
        key_size=SGX_RSA_KEY_SIZE, backend=backends.default_backend())

    raw_sig, signature = sign_with_private_key(data, key)
    public_key = key.public_key()
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    try:
        public_key.verify(signature_bytes, data, padding.PKCS1v15(), hashes.SHA256())
    except cryptography.exceptions.InvalidSignature:
        print(raw_sig.hex())
        print(signature_bytes.hex())
        raise
