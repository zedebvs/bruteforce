import os
import json
import hashlib
import bcrypt
from argon2 import PasswordHasher, exceptions



def clear():
    os.system('cls || clear')
    
def load_data(file_path):
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден")
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Ошибка чтения файла {file_path}: {e}")
        return None

def save_data(file_path, data):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"[+] Файл {file_path} успешно сохранен")
    except Exception as e:
        print(f"Ошибка записи в файл {file_path}: {e}")

def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def sha1_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()

def bcrypt_verify(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def argon2_verify(password: str, hashed_password: str) -> bool:

    ph = PasswordHasher()
    try:
        ph.verify(hashed_password, password)
        return True
    except exceptions.VerifyMismatchError:
        return False

if __name__ == "__main__":
    passw = "adsdasasdads"
    print(bcrypt_verify(passw, "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi"))