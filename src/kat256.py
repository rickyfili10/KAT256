import os
import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import settings  # Importa le impostazioni definite nel modulo settings.py
import json
def generate_key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message

def writePsk(file_path: str, message: str, key: bytes):
    encrypted_message = encrypt_message(message, key)
    with open(file_path, 'wb') as file:
        file.write(encrypted_message)

def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message.decode()
    except ValueError:
        pass

def readPsk(file_path: str) -> bytes:
    with open(file_path, 'rb') as file:
        return file.read()

def save_lock_time(file_path="lock_time.json"):
    lock_time_data = {"lock_time": int(time.time())}
    with open(file_path, 'w') as file:
        json.dump(lock_time_data, file)

def load_lock_time(file_path="lock_time.json"):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                lock_time_data = json.load(file)
                return lock_time_data.get("lock_time", None)
        except (json.JSONDecodeError, FileNotFoundError):
            return None
    return None

def check_lock_time():
    lock_time = load_lock_time()
    if lock_time:
        current_time = int(time.time())
        time_elapsed = current_time - lock_time

        if time_elapsed < settings.block_time:
            remaining_time = settings.block_time - time_elapsed
            print(f"Blocked for {remaining_time} seconds.")
            time.sleep(remaining_time)
            print("Block lifted. You can try again.")
        else:
            print("Block has expired. You can try again.")
    else:
        print("No block active.")

def setPsk(action2):
    original_message = "BlacKat"
    password = input("Create a password: ")
    key = generate_key_from_password(password)
    writePsk("psk.txt", original_message, key)
    print("Password Saved.")
    action2()

def kat256(action):
    check_lock_time()  
    psk_try = 0

    if os.path.exists("psk.txt"):
        encrypted_message = readPsk("psk.txt")
        while psk_try < settings.max_tries:  # Usa max_tries da settings.py
            user_password = input("Password required: ")
            user_key = generate_key_from_password(user_password)
            try:
                decrypted_message = decrypt_message(encrypted_message, user_key)
                if decrypted_message == "BlacKat":
                    action()
                    break
                else:
                    print("Wrong password")
                    psk_try += 1
            except ValueError as e:
                print(str(e))
                psk_try += 1

        if psk_try >= settings.max_tries:
            print(f"Reached max tries")
            save_lock_time()  
            print(f"Blocked for {settings.block_time} seconds...")  # Usa block_time da settings.py
            time.sleep(settings.block_time)  
            print("Block lifted. You can try again.")
    else:
        setPsk(action)
 
