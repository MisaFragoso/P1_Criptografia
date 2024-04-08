from flask import Flask, render_template, request, jsonify, redirect, session
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Clave secreta para manejar sesiones seguras

# Para este ejemplo, usamos una clave AES fija para el cifrado y descifrado
# En una aplicación real, deberías gestionar esta clave de manera segura y posiblemente diferente por usuario/sesión
AES_KEY = os.urandom(16)  # Clave AES de 16 bytes para cifrado simétrico
messages = []

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/chat")
def chat():
    return render_template("index.html", messages=messages)

@app.route("/login", methods=["POST"])
def login():
    # Aquí omitimos la lógica de clave RSA para enfocarnos en AES
    return redirect("/chat")

@app.route("/send_message", methods=["POST"])
def send_message():
    global messages
    username = request.form["username"]
    message = request.form["message"]
    # Cifra el mensaje antes de almacenarlo
    encrypted_message, nonce, tag = encrypt_message(message)
    # Almacenamos el mensaje cifrado con su nonce y tag para permitir el descifrado posterior
    messages.append({"username": username, "message": encrypted_message, "nonce": nonce, "tag": tag})
    return jsonify({"success": True})

@app.route("/get_messages")
def get_messages():
    # Desciframos los mensajes antes de enviarlos
    decrypted_messages = [{"username": msg["username"], "message": decrypt_message(msg["message"], msg["nonce"], msg["tag"])} for msg in messages]
    return jsonify({"messages": decrypted_messages})

def encrypt_message(message):
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    print(cipher)
    ciphertext, tag = cipher.encrypt_and_digest(pad(message.encode(), AES.block_size))
    # Convertimos los bytes a hexadecimal para almacenar y transmitir fácilmente
    return ciphertext.hex(), cipher.nonce.hex(), tag.hex()

def decrypt_message(encrypted_message, nonce, tag):
    # Convertimos de hexadecimal a bytes
    encrypted_message, nonce, tag = bytes.fromhex(encrypted_message), bytes.fromhex(nonce), bytes.fromhex(tag)
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    decrypted_message = unpad(cipher.decrypt_and_verify(encrypted_message, tag), AES.block_size)
    return decrypted_message.decode()

if __name__ == "__main__":
    app.run(debug=True)
