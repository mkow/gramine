from os import urandom

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from graminelibos.sgx_sign import _cryptography_backend, sign_with_private_key

SGX_RSA_PUBLIC_EXPONENT = 3
SGX_RSA_KEY_SIZE = 3072
data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'

while True:
    print('.', end='', flush=True)
    key = rsa.generate_private_key(public_exponent=SGX_RSA_PUBLIC_EXPONENT,
        key_size=SGX_RSA_KEY_SIZE, backend=_cryptography_backend)

    _, _, signature = sign_with_private_key(data, key)
    public_key = key.public_key()
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    public_key.verify(signature_bytes, data, padding.PKCS1v15(), hashes.SHA256())
