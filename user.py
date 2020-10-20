import base64
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class User:

    def __init__(self, name):
        self._name = name.lower()
        self._friends = {}
        self._private_key = None
        self._public_key = None
        validate_users_folder(self._name)
        self.load_data()
        self.my_string = ''

    def load_data(self):
        try:
            if os.path.exists(f'./users_folder/{self._name}/{self._name}_private.pem') and os.stat(f'./users_folder/{self._name}/{self._name}_private.pem').st_size != 0:
                with open(f'./users_folder/{self._name}/{self._name}_private.pem', mode='rb') as private_key_file:
                    self._private_key = serialization.load_pem_private_key(
                        private_key_file.read(),
                        password=None,
                        backend=default_backend()
                    )

            if os.path.exists(f'./users_folder/{self._name}/{self._name}_public.pem') and os.stat(f'./users_folder/{self._name}/{self._name}_public.pem').st_size != 0:
                with open(f'./users_folder/{self._name}/{self._name}_public.pem', mode='rb') as public_key_file:
                    self._public_key = serialization.load_pem_public_key(
                        public_key_file.read(),
                        backend=default_backend()
                    )
            else:
                self.create_user()

        except Exception as x:
            raise x

    # def load_friends(self):
    #     try:
    #         if os.path.exists(f'./users_folder/{self._name}/{self._name}_friends.pem') and os.stat(f'./users_folder/{self._name}/{self._name}_friends.pem').st_size != 0:
    #             with open(f'./users_folder/{self._name}/{self._name}_friends.pem', mode='r') as friends_file:
    #                 for line in friends_file:
    #                     friend_data = line.split(',')
    #                     name = friend_data[0]
    #                     public_key = friend_data[1]
    #                     self.friends[name] = public_key

    #     except Exception as x:
    #         raise x

    def get_friend_public_key(self, friend_name):
        try:
            # for name, public_key in self._friends.items():
            #     if friend_name in name:
            #         return public_key
            friend_public_key = None

            if os.path.exists(f'./users_folder/{friend_name}/{friend_name}_public.pem') and os.stat(f'./users_folder/{friend_name}/{friend_name}_public.pem').st_size != 0:
                with open(f'./users_folder/{friend_name}/{friend_name}_public.pem', mode='rb') as friend_public_key_file:
                    friend_public_key = serialization.load_pem_public_key(
                        friend_public_key_file.read(),
                        backend=default_backend()
                    )

            if friend_public_key is None:
                friend_public_key = ''

            return friend_public_key

        except Exception as x:
            raise x

    def create_user(self):
        try:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            self.store_data(self._private_key, self._public_key)

        except Exception as x:
            raise x

    def store_data(self, private_key, public_key):
        try:
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(f'./users_folder/{self._name}/{self._name}_private.pem', mode='wb+') as f:
                f.write(pem_private)

            with open(f'./users_folder/{self._name}/{self._name}_public.pem', mode='wb+') as f:
                f.write(pem_public)

        except Exception as x:
            raise x

    def encrypt_message(self, friend_public_key, message):
        # TODO: REVER
        try:
            print_data(f'FROM USER - ENCRYPT (TYPE)-> {type(message)}')
            print_data(f'FROM USER - ENCRYPT -> {message}')
            encrypted_message = friend_public_key.encrypt(
                bytes(message, encoding='utf8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print_data(f'FROM USER - ENCRYPT -> {type(encrypted_message)}')
            print_data(f'FROM USER - ENCRYPT -> {encrypted_message}')
            return encrypted_message

        except Exception as x:
            raise x

    def decrypt_message(self, message):
        # TODO: REVER
        try:
            print_data(f'FROM USER (TYPE) - DECRYPT-> {type(message)}')
            print_data(f'FROM USER - DECRYPT-> {message}')

            # message = base64.b64decode(message)
            # message = message.encode("raw_unicode_escape")

            # print_data(f'FROM USER (TYPE) - DECRYPT-> {type(message)}')
            # print_data(f'FROM USER - DECRYPT-> {message}')
            # private_key = private_key if isinstance(private_key, RSAPrivateKey) else self.load_pem_private_key(
            #     private_key_pem_export=private_key
            # )

            original_message = self._private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # print_data(original_message)
            # return str(original_message)
            return "OI"

        except Exception as x:
            print_data(x)

    def get_public_key(self):
        return self._public_key

    def get_name(self):
        return self._name


def validate_users_folder(name=False):
    try:
        if not name:
            if not os.path.exists('./users_folder'):
                os.makedirs('./users_folder')
        else:
            if not os.path.exists(f'./users_folder/{name}'):
                os.makedirs(f'./users_folder/{name}')

    except Exception as x:
        print(x)


def print_data(message):
    with open('./output.txt', 'a+') as file:
        file.write(f"{message}\n")


def convert_string_to_bytes(string):
    bytes = b''
    for i in string:
        bytes += struct.pack("B", ord(i))
    return bytes
