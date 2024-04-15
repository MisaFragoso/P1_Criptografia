# -*- coding: utf-8 -*-
# SECURE CHAT - DEMO
#
# Authors: - Fragoso Alarcón Alejandro Misael   315077757
#          - Jimenez García Rodrigo Gaudencio   317296103
#          - Oronzor Montes Manases Leonel      421099535
#          - Pérez Pérez Alberto Guadalupe      317022832
#          - Ramos Rosas Luis Carlos	        317226944
# Date: 2024.04.04
# License: MIT

from flask import Flask, render_template, request, jsonify, redirect
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

app = Flask(__name__)  # Inicializa la aplicación Flask

# Variables para almacenar usuarios, mensajes, y claves criptográficas
users = {} 
messages = []
symmetric_key = None
private_key = None
public_key = None

# Función para firmar un mensaje hash con una clave privada
def sign_message(message_hash, private_key):
    hasher = SHA256.new(bytes.fromhex(message_hash))  
    signature = pkcs1_15.new(private_key).sign(hasher)
    return signature

# Función para encriptar un mensaje usando una clave simétrica
def encrypt_symmetric(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce

# Función para desencriptar un mensaje usando una clave simétrica
def decrypt_symmetric(ciphertext, tag, nonce, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except ValueError as e:
        print("Decryption failed or tag verification failed:", e)
        return None

# Función para encriptar datos con clave pública RSA
def encrypt_asymmetric(data, public_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher_rsa.encrypt(data)
        return encrypted_data
    except Exception as e:
        print("Failed to encrypt with RSA:", str(e))
        return None

# Función para desencriptar datos con clave privada RSA
def decrypt_asymmetric(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data = cipher_rsa.decrypt(encrypted_data)
    return data

# Función para hashear un mensaje
def hash_message(message):
    hash_object = hashlib.sha256()
    hash_object.update(message) 
    return hash_object.hexdigest()

# Función para derivar una clave utilizando PBKDF2
def pbkdf2(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Función para crear claves RSA y almacenarlas en archivos
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

# Función para importar claves desde archivos
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

# Rutas y controladores de Flask para la aplicación web
@app.route("/")
def index():
    if symmetric_key:
        return redirect("/user2")
    else:
        return render_template("login.html")

@app.route("/chat")
def chat():
    # Verifica si existe una clave simétrica; si existe, carga la página del chat.
    # Si no existe, redirige al usuario a la página de inicio para que inicie sesión.
    if symmetric_key:
        return render_template("index.html", messages=messages, users=users)
    else:
        return redirect("/")

@app.route("/login", methods=["POST"])
def login():
    # Procesa la información de login, crea o importa claves RSA y establece una clave simétrica.
    # Guarda las claves y el nombre de usuario en el diccionario 'users'.
    global symmetric_key, private_key, public_key
    secret = request.form["secret"]
    username = request.form["username"]
    key_location = request.form["key_location"]
    private_key_path = os.path.join(key_location, f"{username}_private.pem")
    public_key_path = os.path.join(key_location, f"{username}_public.pem")

    if secret and 'private_key' in request.files:
        create_keys(secret, private_key_path, public_key_path)

    private_key, public_key = import_keys(private_key_path, public_key_path, secret)

    if private_key is None or public_key is None:
        print("Error importing keys")
        return redirect("/")

    password = bytes(secret, 'utf-8')
    salt = get_random_bytes(16)
    symmetric_key = pbkdf2(password, salt, 32)

    users[username] = {
        "symmetric_key": symmetric_key,
        "private_key": private_key,
        "public_key": public_key
    }

    return redirect("/chat")

@app.route("/send_message", methods=["POST"])
def send_message():
    # Maneja el envío de mensajes cifrados entre usuarios. Los mensajes se cifran simétricamente y se añaden a la lista de mensajes.
    global messages, symmetric_key, users

    if not symmetric_key:
        return jsonify({"error": "You must be logged in to send messages."}), 403

    sender = request.form["sender"]
    recipient = request.form["recipient"]
    message = request.form["message"]

    if sender not in users or recipient not in users:
        return jsonify({"error": "Sender or recipient not registered."}), 403
    try:
        ciphertext, tag, nonce = encrypt_symmetric(message, users[recipient]["symmetric_key"])
        message_hash = hash_message(ciphertext)
        signature = sign_message(message_hash, users[sender]["private_key"])
        encrypted_symmetric_key = encrypt_asymmetric(users[recipient]["symmetric_key"], users[recipient]["public_key"])

        if encrypted_symmetric_key is None:
            return jsonify({"error": "Failed to encrypt symmetric key."}), 500

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
        print("Encrypted RSA message:", base64.b64encode(encrypted_symmetric_key).decode())
        print("Decrypted message:", message)
        print("Tag:", base64.b64encode(tag).decode())
        print("Nonce (IV):", base64.b64encode(nonce).decode())
        print("Hashed Message:", message_hash)
    except Exception as e:
        print("Error during message sending:", str(e))
        return jsonify({"error": "An error occurred during message sending."}), 500
    
    try:
        verifier = pkcs1_15.new(users[sender]["public_key"])
        hasher = SHA256.new(bytes.fromhex(message_hash))
        verifier.verify(hasher, signature)
        print("Signature is valid.")
    except (ValueError, TypeError):
        print("Signature is invalid.")
        return jsonify({"error": "Signature verification failed."}), 500
    return jsonify({"sender": sender, "recipient": recipient, "message": message})

@app.route("/get_messages")
def get_messages():
    # Retorna todos los mensajes en un formato serializado, incluyendo información sobre la criptografía utilizada.
    global messages
    serialized_messages = []
    for message in messages:
        base64_ciphertext = base64.b64encode(message["ciphertext"]).decode('utf-8')
        base64_tag = base64.b64encode(message["tag"]).decode('utf-8')
        base64_nonce = base64.b64encode(message["nonce"]).decode('utf-8')
        base64_encrypted_symmetric_key = base64.b64encode(message["encrypted_symmetric_key"]).decode('utf-8')
        base64_signature = base64.b64encode(message["signature"]).decode('utf-8')

        decrypted_message = decrypt_symmetric(message["ciphertext"], message["tag"], message["nonce"], users[message["recipient"]]["symmetric_key"])
        message_text = decrypted_message if decrypted_message else "Failed to decode message"

        serialized_message = {
            "sender": message["sender"],
            "recipient": message["recipient"],
            "message": message_text,
            "ciphertext": base64_ciphertext,
            "tag": base64_tag,
            "nonce": base64_nonce,
            "encrypted_symmetric_key": base64_encrypted_symmetric_key,
            "message_hash": message["message_hash"],
            "signature": base64_signature
        }
        serialized_messages.append(serialized_message)

    return jsonify({"messages": serialized_messages})

@app.route("/user2")
def user2():
    # Redirecciona al usuario a la página de inicio si aún no se ha autenticado con una clave simétrica.
    return render_template("login.html")

@app.route("/logout", methods=['POST'])
def logout():
    # Limpia todas las claves y mensajes al cerrar sesión.
    global symmetric_key, private_key, public_key, messages, users
    symmetric_key = None
    private_key = None
    public_key = None
    messages.clear()
    users.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
