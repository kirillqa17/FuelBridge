import base64
import binascii
import hashlib
import msvcrt
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from web3 import Web3


def is_base64(s):
    if not len(s):
        return False
    try:
        if len(s) == 64:
            Web3().eth.account.from_key(s)
            return False
    except Exception:
        ...
    try:
        decoded = base64.b64decode(s)
        reencoded = base64.b64encode(decoded)
        return reencoded == s.encode()
    except Exception:
        return False


def get_cipher(password):
    salt = hashlib.sha256(password.encode('utf-8')).digest()
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=1)
    return AES.new(key, AES.MODE_ECB)


def decrypt_private_key(encrypted_base64_pk, password):
    cipher = get_cipher(password)
    encrypted_pk = base64.b64decode(encrypted_base64_pk)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_pk), 16)
    decrypted_hex = binascii.hexlify(decrypted_bytes).decode()
    if len(decrypted_hex) in (66, 42):
        decrypted_hex = decrypted_hex[2:]
    return '0x' + decrypted_hex


def get_password(prompt="Введите пароль для расшифровки: "):
    """
    Ввод пароля с отображением звездочек (*) вместо вводимых символов.
    Поддерживает любые печатаемые символы, включая цифры, буквы и специальные символы.

    :param prompt: Строка приглашения для ввода пароля.
    :return: Введённый пароль в виде строки.
    """
    import sys
    import os

    if os.name == 'nt':
        # Реализация для Windows
        print(prompt, end='', flush=True)
        password = ""
        while True:
            ch = msvcrt.getch()
            if ch in {b'\r', b'\n'}:
                print('')
                break
            elif ch == b'\x03':
                # Обработка Ctrl+C
                raise KeyboardInterrupt
            elif ch in {b'\x08', b'\x7f'}:
                # Обработка Backspace/Delete
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch.decode('utf-8').isprintable():
                password += ch.decode('utf-8')
                sys.stdout.write('*')
                sys.stdout.flush()
        return password
    else:
        # Реализация для Unix-подобных систем
        import tty
        import termios

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            print(prompt, end='', flush=True)
            password = ""
            while True:
                ch = sys.stdin.read(1)
                if ch in ('\r', '\n'):
                    print('')
                    break
                elif ch == '\x03':
                    # Обработка Ctrl+C
                    raise KeyboardInterrupt
                elif ch in ('\x7f', '\b'):
                    # Обработка Backspace/Delete
                    if len(password) > 0:
                        password = password[:-1]
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                elif ch.isprintable():
                    password += ch
                    sys.stdout.write('*')
                    sys.stdout.flush()
            return password
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def get_wallet_info_from_file(file_path="wallets.txt"):
    """
    Считывает информацию о кошельках из файла. Поддерживает как зашифрованные, так и незашифрованные ключи.
    Проверяет, зашифрован ли файл, по первой строке. Если да, запрашивает пароль один раз для всех строк.

    :param file_path: Путь к файлу с ключами.
    :return: Список пар (адрес, приватный ключ).
    """
    wallets = []

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Файл '{file_path}' не найден.")
    if os.path.getsize(file_path) == 0:
        raise ValueError(f"Файл '{file_path}' пуст. Добавьте кошельки в файл.")

    with open(file_path, "r") as file:
        lines = [line.strip() for line in file if line.strip()]
        if not lines:
            raise ValueError(f"Файл '{file_path}' пуст. Добавьте кошельки в файл.")

        # Определяем, зашифрованы ли ключи, по первой строке
        first_line = lines[0]
        encrypted = is_base64(first_line)

        if encrypted:
            # Запрашиваем пароль один раз
            password = None
            while True:
                try:
                    password = get_password("Введите пароль для расшифровки ключей: ").strip()
                    # Проверяем пароль на первой строке
                    decrypt_private_key(first_line, password)
                    break  # Если расшифровка успешна, выходим из цикла
                except (ValueError, UnicodeDecodeError):
                    print("Неверный пароль, попробуйте снова.")
                except Exception as e:
                    raise ValueError(f"Ошибка проверки пароля: {e}")

        for line_num, line in enumerate(lines, start=1):
            try:
                if encrypted:
                    # Расшифровываем приватный ключ
                    private_key = decrypt_private_key(line, password)
                else:
                    # Незашифрованный ключ
                    private_key = line

                # Получаем адрес кошелька из приватного ключа
                wallet_address = Web3().eth.account.from_key(private_key).address
                wallets.append((wallet_address, private_key))
            except Exception as e:
                print(f"Ошибка обработки строки {line_num} ('{line}'): {e}")

    return wallets
