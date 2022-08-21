import argparse
from getpass import getpass
from typing import Any


class Password(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Any, option_string) -> None:
        if values is None:
            values = getpass()
        setattr(namespace, self.dest, values)


class Crypt:
    pass


class Encrypt(Crypt):
    pass


class Decrypt(Crypt):
    pass

    
def correct_file(name: str):
    if not name.endswith('.txt'):
        raise argparse.ArgumentError()
    return name

def main(arg):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Skrypt do szyfrowania i deszyfrowania plików', epilog='Enjoy!')
    parser.add_argument('-m', '--mode', choices=['encrypt', 'decrypt'], required=True, help='Wybór trybu pracy programu')
    parser.add_argument('-v', '--verbose', action='count', default=0)
    parser.add_argument('-p', '--password', required=True, nargs='?', dest='password', action=Password,help='Hasło')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', type=correct_file, help='Lista pojedynczych plików do zaszyfrowania' )
    group.add_argument('-d', '--dir', help='Folder w którym wszystkie pliki txt zostaną zaszyfrowane')
    args = parser.parse_args()

    main(args)
