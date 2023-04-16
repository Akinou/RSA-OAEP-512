from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem, private_key_pem

def encrypt(public_key, message):
    public_key = serialization.load_pem_public_key(public_key)
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    return ciphertext

def decrypt(private_key, ciphertext):
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None
    )
    message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    return message.decode()

public_key, private_key = generate_key_pair()

message = "Bonjour, comment ça va?"
ciphertext = encrypt(public_key, message)
print("Message chiffré:", ciphertext.hex())

decrypted_message = decrypt(private_key, ciphertext)
print("Message déchiffré:", decrypted_message)
