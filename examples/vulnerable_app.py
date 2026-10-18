from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

rsa_key = RSA.generate(2048)

ecc_key = ec.generate_private_key(
    ec.SECP256R1()
)

another_rsa_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)