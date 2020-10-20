import base64
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
# https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples


class UserCrypto:

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
                    self._private_key = RSA.import_key(private_key_file.read())

            if os.path.exists(f'./users_folder/{self._name}/{self._name}_public.pem') and os.stat(f'./users_folder/{self._name}/{self._name}_public.pem').st_size != 0:
                with open(f'./users_folder/{self._name}/{self._name}_public.pem', mode='rb') as public_key_file:
                    self._public_key = RSA.import_key(public_key_file.read())
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
                    friend_public_key = RSA.import_key(
                        friend_public_key_file.read())

            if friend_public_key is None:
                friend_public_key = ''

            return friend_public_key

        except Exception as x:
            raise x

    def create_user(self):
        try:
            key = RSA.generate(2048)
            self._private_key = key.export_key()
            self._public_key = key.publickey().export_key()
            self.store_data(self._private_key, self._public_key)

        except Exception as x:
            raise x

    def store_data(self, private_key, public_key):
        try:
            with open(f'./users_folder/{self._name}/{self._name}_private.pem', mode='wb+') as f:
                f.write(private_key)

            with open(f'./users_folder/{self._name}/{self._name}_public.pem', mode='wb+') as f:
                f.write(public_key)

        except Exception as x:
            raise x

    def encrypt_message(self, friend_public_key, message):
        # TODO: REVER
        try:
            session_key = get_random_bytes(16)

            # Encrypt the session key with the public RSA key
            cipher_rsa = PKCS1_OAEP.new(friend_public_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            store_last_session(enc_session_key)

            # Encrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message)
            store_last_tag(tag)

            return ciphertext

        except Exception as x:
            raise x

    def decrypt_message(self, message):
        # TODO: REVER
        try:
            # print_data(f'FROM USER (TYPE)-> {type(message)}')
            # print_data(f'FROM USER-> {message}')
            # Decrypt the session key with the private RSA key
            cipher_rsa = PKCS1_OAEP.new(self._private_key)
            session_key = cipher_rsa.decrypt(get_last_session())

            # Decrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            data = cipher_aes.decrypt_and_verify(message, get_last_tag())

            return data.decode("utf-8")

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

        if not os.path.exists(f'./session_folder/'):
            os.makedirs(f'./session_folder/')

        if not os.path.exists(f'./tag_folder/'):
            os.makedirs(f'./tag_folder/')

    except Exception as x:
        print(x)


def print_data(message):
    with open('./output.txt', 'a+') as file:
        file.write(f"{message}\n")


def store_last_session(received_session):
    try:
        with open(f'./session_folder/last_session.pem', mode='wb+') as last_session_file:
            last_session_file.write(received_session)

    except Exception as x:
        print(x)


def get_last_session():
    try:
        if os.path.exists('./session_folder/last_session.pem') and os.stat('./session_folder/last_session.pem').st_size != 0:
            with open(f'./session_folder/last_session.pem', mode='rb') as last_session_file:
                return last_session_file.read()

    except Exception as x:
        print(x)


def store_last_tag(received_tag):
    try:
        with open(f'./tag_folder/last_tag.pem', mode='wb+') as last_tag_file:
            last_tag_file.write(received_tag)

    except Exception as x:
        print(x)


def get_last_tag():
    try:
        if os.path.exists('./tag_folder/last_tag.pem') and os.stat('./tag_folder/last_tag.pem').st_size != 0:
            with open(f'./tag_folder/last_tag.pem', mode='rb') as last_tag_file:
                return last_tag_file.read()

    except Exception as x:
        print(x)
