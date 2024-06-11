import hashlib
import os
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import yaml



def load_config():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
        encrypt_algorithm = getattr(algorithms, config['ENCRYPTION']['ENCRYPT_ALGORITHM'])
        key_size = int(config['ENCRYPTION']['KEY_SIZE'])
        cipher_mode = getattr(modes, config['ENCRYPTION']['CIPHER_MODE'])
        iv_size = int(config['ENCRYPTION']['IV_SIZE'])

    return encrypt_algorithm, key_size, cipher_mode, iv_size


ENCRYPT_ALGORITHM, KEY_SIZE, CIPHER_MODE, IV_SIZE = load_config()


def encrypt_key(private_key, pin):
    hashed_pin = hashlib.sha256(pin.encode()).digest()

    initial_vector = os.urandom(IV_SIZE)
    cipher = Cipher(ENCRYPT_ALGORITHM(hashed_pin), CIPHER_MODE(initial_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )) + encryptor.finalize()

    return encrypted_key, initial_vector


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def save_keys(encrypted_private_key, public_key, iv):
    file_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                             title="Wybierz lokalizacje do zapisania klucza prywatnego")
    if file_path:
        with open(file_path, "wb") as f:
            f.write(encrypted_private_key)
            f.write(iv)
        print("Private key saved to:", file_path)
    file_path = os.path.join('../key/', "public_key.pem")
    os.makedirs('../key/', exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print("Public key saved to:", file_path)


def keygen():
    private_key, public_key = generate_rsa_keys()
    print(private_key)
    pin = input("Enter your PIN: ")
    encrypted_key, iv = encrypt_key(private_key, pin)

    save_keys(encrypted_key, public_key, iv)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    keygen()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
