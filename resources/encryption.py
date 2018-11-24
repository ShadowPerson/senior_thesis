import os
import json
import time
import getpass
from progress.bar import IncrementalBar
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5

PASSWORD_MD5 = b'I\xf6\x8a\\\x84\x93\xec,\x0b\xf4\x89\x82\x1c!\xfc;'
DIRECTORY = os.path.join("..", "Senior_Thesis")


def pad(message):
    return message + b"\0" * (AES.block_size - len(message) % AES.block_size)


def encrypt(message, key):
    padded_message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return iv + cipher.encrypt(padded_message)


def encrypt_file(file_path, end_path, key):
    with open(file_path, "rb") as file_pointer:
        file_text = file_pointer.read()
    encrypted_text = encrypt(file_text, key)

    with open(end_path, "wb") as file_pointer:
        file_pointer.write(encrypted_text)

    if file_path != end_path:
        os.remove(file_path)


def decrypt(encrypted_text, key):
    iv = encrypted_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    original_text = cipher.decrypt(encrypted_text[AES.block_size:])
    return original_text.rstrip(b"\0")


def decrypt_file(file_path, end_path, key):
    with open(file_path, 'rb') as file_pointer:
        encrypted_text = file_pointer.read()
    original_text = decrypt(encrypted_text, key)
    with open(end_path, 'wb') as file_pointer:
        file_pointer.write(original_text)
    if file_path != end_path:
        os.remove(file_path)


def get_sha(text):
    hasher = SHA256.new(text.encode("utf-8"))
    return hasher.digest()[:16]


def get_md5(text):
    hasher = MD5.new(text.encode("utf-8"))
    return hasher.digest()


def encrypt_file_system(dir_path, key, progress_bar=None):
    names = {}

    for i, file_name in enumerate(os.listdir(dir_path)):
        end_name = "{}.pcrypt".format(i)
        names[end_name] = file_name

        file_path = os.path.join(dir_path, file_name)
        end_path = os.path.join(dir_path, end_name)

        if os.path.isfile(file_path):
            encrypt_file(file_path, end_path, key)
        elif os.path.isdir(file_path):
            encrypt_file_system(file_path, key, progress_bar=progress_bar)
            os.rename(file_path, end_path)
        else:
            raise RuntimeError("Unknown file type: {}".format(file_path))

        if progress_bar:
            progress_bar.next()

    write_names_file(dir_path, names, key)


def write_names_file(dir_path, names, key):
    file_path = os.path.join(dir_path, "n.pcrypt")
    with open(file_path, "w") as file_pointer:
        json.dump(names, file_pointer)
    encrypt_file(file_path, file_path, key)


def load_names_file(dir_path, key):
    file_path = os.path.join(dir_path, "n.pcrypt")
    decrypt_file(file_path, file_path, key)
    with open(file_path, "r") as file_pointer:
        names = json.load(file_pointer)
    return names


def decrypt_file_system(dir_path, key, progress_bar=None):
    names = load_names_file(dir_path, key)
    os.remove(os.path.join(dir_path, "n.pcrypt"))

    for encrypted_file in os.listdir(dir_path):
        file_path = os.path.join(dir_path, encrypted_file)
        end_path = os.path.join(dir_path, names[encrypted_file])

        if os.path.isfile(file_path):
            decrypt_file(file_path, end_path, key)
        elif os.path.isdir(file_path):
            decrypt_file_system(file_path, key, progress_bar=progress_bar)
            os.rename(file_path, end_path)
        else:
            raise RuntimeError("Unknown file type: {}".format(file_path))

        if progress_bar:
            progress_bar.next()


def main():
    if "n.pcrypt" in os.listdir(DIRECTORY):
        print("The file system is currently encrypted. Continue to decrypt.")
        encrypted = True
    else:
        print("The file system is currently decrypted. Continue to encrypt.")
        encrypted = False
        
    password = getpass.getpass("Enter password: ")
##    password = input("password: ")
    if encrypted and password_is_correct(password):
        progress_bar = IncrementalBar("Decrypting", max=get_encrypted_file_count(DIRECTORY) - 1)
        
        key = get_sha(password)
        decrypt_file_system(DIRECTORY, key, progress_bar=progress_bar)

        progress_bar.finish()
    elif encrypted:
        print("That password was incorrect.")
    else:
##        if input("password: ") == password:
        if getpass.getpass("Confirm password: ") == password:
            progress_bar = IncrementalBar("Encrypting", max=get_decrypted_file_count(DIRECTORY))
            
            set_password(password)
            key = get_sha(password)
            encrypt_file_system(DIRECTORY, key, progress_bar=progress_bar)
            
            progress_bar.finish()
        else:
            print("The second password did not match the first.")
    print("Done.")
            
    time.sleep(3)


def get_encrypted_file_count(directory):
    count = 0
    for file_obj in os.listdir(directory):
        path = os.path.join(directory, file_obj)
        if os.path.isdir(path):
            count += get_encrypted_file_count(path)
        else:
            count += 1
    return count


def get_decrypted_file_count(directory):
    count = 0
    for file_obj in os.listdir(directory):
        path = os.path.join(directory, file_obj)
        if os.path.isdir(path):
            count += get_decrypted_file_count(path) + 1
        else:
            count += 1
    return count

def set_password(password):
    with open("data.txt", "wb") as password_file:
        password_file.write(get_md5(password))


def password_is_correct(password):
    with open("data.txt", "rb") as password_data:
        correct_password = password_data.read()
    return get_md5(password) == correct_password


if __name__ == '__main__':
    main()
