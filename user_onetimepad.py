import os

import hashlib
import onetimepad


class UserOneTimePad:

    def __init__(self, name):
        self._name = name.lower()
        self._friends = {}
        self._key = None
        validate_users_folder(self._name)
        self.load_data()

    def load_data(self):
        try:
            if os.path.exists(f'./users_folder/{self._name}/{self._name}_key.pem') and os.stat(f'./users_folder/{self._name}/{self._name}_key.pem').st_size != 0:
                with open(f'./users_folder/{self._name}/{self._name}_key.pem', mode='rb') as key_file:
                    self._key = key_file.read().decode('utf-8')

            else:
                self.create_user()

        except Exception as x:
            raise x

    def create_user(self):
        try:
            self._key = 'root'
            self.store_data(self._key)
            self.load_data()

        except Exception as x:
            raise x

    def store_data(self, private_key: str):
        try:
            with open(f'./users_folder/{self._name}/{self._name}_key.pem', mode='wb+') as f:
                hex = hashlib.md5(
                    bytes(private_key, 'utf-8')).hexdigest()
                data = hex.encode('utf-8')
                f.write(data)

        except Exception as x:
            raise x

    def encrypt_message(self, message):
        # TODO: REVER
        try:
            ciphertext = onetimepad.encrypt(message, self._key)
            return ciphertext

        except Exception as x:
            raise x

    def decrypt_message(self, message):
        # TODO: REVER
        try:
            msg = onetimepad.decrypt(message, self._key)
            print_data(f"message = {message}")
            print_data(f"{type(message)}")
            print_data(f"msg = {msg}")
            print_data(f"{type(msg)}")
            return msg

        except Exception as x:
            print_data(x)

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
