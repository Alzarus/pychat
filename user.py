import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class User:

    def __init__(self, name):
        validate_users_folder()
        self._name = name
        self._friends = {}
        self._private_key = None
        self._public_key = None
        self.load_data()

    def load_data(self):
        try:
            with open(f'./users_folder/{self._name}.pem', mode='r') as user_file:
                if os.stat(f'./users_folder/{self._name}.pem').st_size != 0:
                    self._private_key = serialization.load_pem_private_key(
                        user_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                    self._public_key = self._private_key.public_key()
                else:
                    self.create_user()

        except Exception as x:
            print(x)

    # TODO: CONTINUAR IMPLEMENTACAO
    def load_friends(self):
        try:
            pass
        except Exception as x:
            print(x)

    def create_user(self):
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            self.store_data(self._private_key)

        except Exception as x:
            print(x)

    def store_data(self, private_key):
        try:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(f'./users_folder/{self._name}.pem', 'wb') as f:
                f.write(pem)

        except Exception as x:
            print(x)

    def encrypt_message(self, friend_public_key, message):
        try:
            encrypted_message = friend_public_key.encrypt(
                bytes(message),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_message.decode("utf-8")

        except Exception as x:
            print(x)

    def decrypt_message(self, message):
        try:
            original_message = self._private_key.decrypt(
                bytes(message),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return original_message.decode("utf-8")

        except Exception as x:
            print(x)

    def get_public_key(self):
        return self._public_key


def validate_users_folder():
    try:
        if not os.path.exists('./users_folder'):
            os.makedirs('./users_folder')

    except Exception as x:
        print(x)
