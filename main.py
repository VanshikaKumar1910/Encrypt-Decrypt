from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
import os


def load_key():
  file = open("key.key", "rb")
  key = file.read()
  file.close()
  return key


def derive_key(password: str, salt: bytes, iterations: int = 100_000):
  password = password.encode()

  kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                   length=32,
                   salt=salt,
                   iterations=iterations,
                   backend=default_backend())

  key = base64.urlsafe_b64encode(kdf.derive(password))

  return key


master_pwd = input("What is the master password? ")
salt = os.urandom(16)
key = derive_key(master_pwd, salt)
fer = Fernet(key)


def view():
  with open('passwords.txt', 'r') as f:
    for line in f.readlines():
      data = line.rstrip()
      if "|" not in data:
        print("Invalid line:", data)
        continue
      user, passw = data.split("|")
      print("User:", user, " | Password:",
            fer.decrypt(passw.encode()).decode())


def add():
  name = input("account name:")
  pwd = input("password: ")

  with open('passwords.txt', 'a') as f:
    f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")


while True:
  mode = input(
      "Would you like to add a new password or view existing ones (view, add)? "
  ).lower()
  if mode == "q":
    break

  if mode == "view":
    view()
  elif mode == "add":
    add()
  else:
    print("Invalid Mode")
    continue
