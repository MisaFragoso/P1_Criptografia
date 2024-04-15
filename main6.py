# -*- coding: utf-8 -*-
# SECURE CHAT - DEMO
#
# Authors: Jimenez García Rodrigo Gaudencio
# Date: 2024.04.04
# License: MIT

from flask import Flask, render_template, request, jsonify, redirect, send_file
from werkzeug.utils import secure_filename
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import hashlib
import os
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import base64

app = Flask(__name__)

users = {}
messages = []
symmetric_key = None
private_key = None
public_key = None
session_id = 0  # Corrected variable name
secret = None

# Función para firmar un mensaje
def sign_message(message, private_key):
    hasher = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(hasher)
    return signature


def encrypt_symmetric(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce


def encrypt_asymmetric(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data


def decrypt_asymmetric(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data = cipher_rsa.decrypt(encrypted_data)
    return data


def hash_message(message):
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    return hash_object.hexdigest()


def pbkdf2(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def create_keys(secret, private_key_path, public_key_path):
    try:
        key = RSA.generate(2048)
        private_key = key.export_key(passphrase=secret)
        public_key = key.publickey().export_key()
        with open(private_key_path, "wb") as f:
            f.write(private_key)
        with open(public_key_path, "wb") as f:
            f.write(public_key)
        return render_template("login.html")
    except Exception as e:
        print(f"Error creating keys: {e}")
        return None


def import_keys(private_key_path, public_key_path, secret):
    try:
        with open(private_key_path, "rb") as f:
            private_key = RSA.import_key(f.read(), passphrase=secret)
        print("Private key imported successfully")

        with open(public_key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        print("Public key imported successfully")

        return private_key, public_key
    except (IOError, ValueError, Exception) as e:
        print(f"Error importing keys: {e}")
        return None, None



@app.route("/")
def index():
    if symmetric_key:
        return redirect("/user2")  # Redirige a /user2 si ya hay una sesión activa
    else:
        return render_template("login.html")


@app.route("/chat")
def chat():
    if symmetric_key:
        return render_template("index.html", messages=messages, users=users)
    else:
        return redirect("/")
    
@app.route("/login", methods=["POST"])
def login():
    global symmetric_key, private_key, public_key
    secret = request.form["secret"]
    username = request.form["username"]
    key_location = request.form["key_location"]
    private_key_path = os.path.join(key_location, f"{username}_private.pem")
    public_key_path = os.path.join(key_location, f"{username}_public.pem")

    # Verifica si se proporcionó un secreto y se subió un archivo de clave privada
    if secret and 'private_key' in request.files:
        # Crea las claves RSA si aún no existen
        create_keys(secret, private_key_path, public_key_path)

    # Intenta importar las claves privada y pública
    private_key, public_key = import_keys(private_key_path, public_key_path, secret)

    # Verifica si las claves se importaron correctamente
    if private_key is None or public_key is None:
        print("Error importing keys")
        return redirect("/")

    # Genera la clave simétrica
    password = bytes(secret, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf2(password, salt, 32)

    # Almacena las claves y la clave simétrica en la sesión del usuario
    users[username] = {
        "symmetric_key": symmetric_key,
        "private_key": private_key,
        "public_key": public_key
    }

    print("RSA private key:")
    print(private_key.export_key().decode())
    print("\nRSA public key:")
    print(public_key.export_key().decode())
    print("\nGenerated salt:", salt.hex())
    print("Derived symmetric key:", symmetric_key.hex())

    return redirect("/chat")


    # Si no se proporciona un secreto ni se carga un archivo de clave privada, redirige a la página principal
    if not secret and not request.files['private_key']:
        return redirect("/")

    password = bytes(secret, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf2(password, salt, 32)

    users[username] = {
        "symmetric_key": symmetric_key,
        "private_key": private_key,
        "public_key": public_key
    }

    print("RSA private key:")
    print(private_key.export_key().decode())
    print("\nRSA public key:")
    print(public_key.export_key().decode())
    print("\nGenerated salt:", salt.hex())
    print("Derived symmetric key:", symmetric_key.hex())

    return redirect("/chat")


@app.route("/send_message", methods=["POST"])
def send_message():
    global messages, symmetric_key, users

    if not symmetric_key:
        return jsonify({"error": "You must be logged in to send messages."}), 403

    sender = request.form["sender"]
    recipient = request.form["recipient"]
    message = request.form["message"]

    # Verifica que tanto el remitente como el destinatario están registrados y tienen claves
    if sender not in users or recipient not in users:
        print(f"One of the users is not registered: sender={sender}, recipient={recipient}")
        return jsonify({"error": "Sender or recipient not registered."}), 403

    message_hash = hash_message(message)
    signature = sign_message(message_hash, users[sender]["private_key"])

    try:
        ciphertext, tag, nonce = encrypt_symmetric(message, users[recipient]["symmetric_key"])
        encrypted_symmetric_key = encrypt_asymmetric(users[recipient]["symmetric_key"], users[recipient]["public_key"])
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return jsonify({"error": "Encryption failed."}), 500

    messages.append({
        "sender": sender,
        "recipient": recipient,
        "message": message,
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": nonce,
        "encrypted_symmetric_key": encrypted_symmetric_key,
        "message_hash": message_hash,
        "signature": signature
    })

    print("\nEncrypted RSA message:", base64.b64encode(encrypted_symmetric_key).decode())
    print("Decrypted message:", message)
    print("Tag:", base64.b64encode(tag).decode())
    print("Nonce (IV):", base64.b64encode(nonce).decode())
    print("Message integrity:")

    try:
        pkcs1_15.new(users[sender]["public_key"]).verify(SHA256.new(message_hash.encode()), signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")
        return jsonify({"error": "Signature verification failed."}), 500

    return jsonify({"sender": sender, "recipient": recipient, "message": message})

@app.route("/get_messages")
def get_messages():
    global messages
    serialized_messages = []
    for message in messages:
        serialized_message = {
            "sender": message["sender"],
            "recipient": message["recipient"],
            "message": message["message"],
            "ciphertext": base64.b64encode(message["ciphertext"]).decode(),
            "tag": base64.b64encode(message["tag"]).decode(),
            "nonce": base64.b64encode(message["nonce"]).decode(),
            "encrypted_symmetric_key": base64.b64encode(message["encrypted_symmetric_key"]).decode(),
            "message_hash": message["message_hash"],
            "signature": base64.b64encode(message["signature"]).decode()
        }
        serialized_messages.append(serialized_message)
    return jsonify({"messages": serialized_messages})


@app.route("/user2")
def user2():
  return render_template("login.html")

@app.route("/logout", methods=['POST'])
def logout():
    global symmetric_key, private_key, public_key, messages, users
    symmetric_key = None
    private_key = None
    public_key = None
    messages.clear()
    users.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)