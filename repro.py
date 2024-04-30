from os import urandom

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from graminelibos.sgx_sign import (sign_with_private_key_from_pem_path, SGX_RSA_KEY_SIZE, SGX_RSA_PUBLIC_EXPONENT,
    _cryptography_backend, sign_with_private_key)

def verify_signature(data, signature, key_file, passphrase=None):
    private_key = serialization.load_pem_private_key(key_file.read(), password=passphrase,
        backend=_cryptography_backend)

    public_key = private_key.public_key()

    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
    public_key.verify(signature_bytes, data, padding.PKCS1v15(), hashes.SHA256())

data = b'lorem ipsum dolor sit amet consectetur adipiscing elit'

key_path = f'/tmp/pytest_debugging/key_{urandom(16).hex()}.pem'
print(f'{key_path}')
while True:
    print('.', end='', flush=True)
    with open(key_path, 'wb') as pfile:
        key = rsa.generate_private_key(public_exponent=SGX_RSA_PUBLIC_EXPONENT,
            key_size=SGX_RSA_KEY_SIZE, backend=_cryptography_backend)

        private_key = key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        pfile.write(private_key)
    with open(key_path, 'rb') as key_file:
        # _, _, signature = sign_with_private_key_from_pem_path(data, key_path)
        _, _, signature = sign_with_private_key(key)
        verify_signature(data, signature, key_file)
