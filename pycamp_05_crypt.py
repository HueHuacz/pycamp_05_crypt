import argparse
import base64
import pathlib
from getpass import getpass
from typing import Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class Password(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Any, option_string) -> None:
        if values is None:
            values = getpass()
        setattr(namespace, self.dest, values)


class Crypt:
    def __init__(self, path):
        self.path = path

    @staticmethod
    def create_key(password):
        salt = b'\xda\x01\xac\x87'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key


class Encrypt(Crypt):
    def execute(self, password):
        with open(self.path, 'r') as file:
            data_to_encrypt = file.read()

        fernet = Fernet(self.create_key(password))
        encrypted_data = fernet.encrypt(data_to_encrypt.encode('utf-8'))

        with open(self.path.rename(self.path.with_suffix('.mycrypt')), 'w') as file:
            file.write(encrypted_data.decode('utf-8'))


class Decrypt(Crypt):
    def execute(self, password):
        with open(self.path, 'r') as file:
            data_to_dencrypt = file.read()

        fernet = Fernet(self.create_key(password))
        decrypted_data = fernet.decrypt(data_to_dencrypt.encode('utf-8'))

        with open(self.path.rename(self.path.with_suffix('.txt')), 'w') as file:
            file.write(decrypted_data.decode('utf-8'))


def correct_file(name: str):
    if not name.endswith(('.txt', '.mycrypt')):
        raise argparse.ArgumentError()
    return name


def main(arg):
    if args.mode == 'encrypt':
        path = pathlib.Path(args.file)
        action = Encrypt(path)
        action.execute(args.password)

    if args.mode == 'decrypt':
        path = pathlib.Path(args.file)
        action = Decrypt(path)
        action.execute(args.password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Skrypt do szyfrowania i deszyfrowania plików', epilog='Enjoy!')
    parser.add_argument('-m', '--mode', choices=['encrypt', 'decrypt'], required=True, help='Wybór trybu pracy programu')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('-p', '--password', required=True, nargs='?', dest='password', action=Password, help='Hasło')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', type=correct_file, help='Lista pojedynczych plików do zaszyfrowania')
    group.add_argument('-d', '--dir', help='Folder w którym wszystkie pliki txt zostaną zaszyfrowane')
    args = parser.parse_args()

    main(args)
