from flask import Flask, render_template, request, jsonify, redirect, send_file
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES, PKCS1_OAEP
import hashlib
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

app = Flask(__name__)

messages = []
symmetric_key = None
private_key = None
public_key = None

def sign_message(message, private_key):
    key = private_key
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def encrypt_symmetric(message, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def encrypt_asymmetric(data, public_key):
    recipient_key = public_key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def hash_message(message):
    hash_object = hashlib.sha256()
    hash_object.update(message.encode())
    return hash_object.hexdigest()

def pbkdf(password, salt, length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

@app.route("/")
def index():
    if symmetric_key:
        return redirect("/chat")
    else:
        return render_template("login.html")

@app.route("/chat")
def chat():
    if symmetric_key:
        return render_template("index.html", messages=messages)
    else:
        return redirect("/")

@app.route("/login", methods=["POST"])
def login():
    global symmetric_key, private_key, public_key
    secret = request.form["secret"]
    key_location = request.form["key_location"]

    if not secret and not request.files['private_key']: 
        return redirect("/")

    private_key_path = os.path.join(key_location, "private.pem")
    public_key_path = os.path.join(key_location, "public.pem")

    if os.path.exists(public_key_path and private_key_path):
        try:
            # Importar clave privada con contraseña
            with open(private_key_path, "rb") as f:
                private_key_data = f.read()  # Leer los datos completos de la clave como bytes
            private_key = RSA.import_key(private_key_data, passphrase=secret)

            # Leer datos de clave pública de un archivo
            with open(public_key_path, "rb") as f:
                public_key_data = f.read()

            # Asegurarse de que los datos estén en el formato correcto
            try:
                public_key = RSA.import_key(public_key_data)
                # Si no hay excepción, los datos están en el formato correcto
                print("Clave pública importada correctamente")
            except (ValueError, IndexError) as e:
                # Manejar el error si los datos no están en el formato correcto
                print(f"Error al importar la clave pública: {e}")

        except (IOError, ValueError) as e:
            # Manejar errores de importación de claves
            print(f"Error al importar las claves: {e}")
            return redirect("/")
    else:
        # Generar pareja de claves RSA de 2048 bits de longitud, llaves asimetricas
        key = RSA.generate(2048)
        # Exportamos la clave privada
        private_key = key.export_key(passphrase=secret)
        # Obtenemos la clave pública
        public_key = key.publickey().export_key()
        # Guardar la clave privada en la ubicación especificada por el usuario
        private_key_path = os.path.join(key_location, "private.pem")
        with open(private_key_path, "wb") as f:
             f.write(private_key)
        # Guardar la clave publica en dircetorio de usuarios (falta implementar)
        public_key_path = os.path.join(key_location, "public.pem")
        with open(public_key_path, "wb") as f:
             f.write(public_key)
        send_file(private_key_path, as_attachment=True)
        send_file(public_key_path, as_attachment=True)

        # Derivar clave simétrica usando PBKDF2
        password = bytes(secret, 'utf-8')
        salt = get_random_bytes(16)
        symmetric_key = pbkdf(password, salt, 32)

        # Imprimir información en la terminal
        print("Clave privada RSA:")
        #print(private_key.export_key().decode())
        print("\nClave pública RSA:")
        #print(public_key.export_key().decode())
        print("\nSalt generado:", salt.hex())
        print("Clave simétrica derivada:", symmetric_key.hex())

    return redirect("/chat")

@app.route("/send_message", methods=["POST"])
def send_message():
    global messages, symmetric_key, private_key, public_key
    if not symmetric_key:
        return jsonify({"error": "Debes iniciar sesión para enviar mensajes."}), 403

    username = request.form["username"]
    message = request.form["message"]

    # Cifrar mensaje simétricamente
    ciphertext, tag, nonce = encrypt_symmetric(message, symmetric_key)

    # Importar clave pública desde bytes (asumiendo que ya has leído los datos de la clave pública)
    #public_key_object = RSA.import_key(public_key)  # Usar los datos brutos de bytes aquí

    # Cifrar clave simétrica con clave pública
    encrypted_symmetric_key = encrypt_asymmetric(symmetric_key, public_key)

    # Hash del mensaje
    message_hash = hash_message(message)

    # Firma digital del mensaje (considera usar relleno PSS)
    signature = sign_message(message_hash, private_key)

    messages.append({
        "username": username,
        "message": message,
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": nonce,
        "encrypted_symmetric_key": encrypted_symmetric_key,
        "message_hash": message_hash,
        "signature": signature
    })

    # Imprimir información en la terminal
    print("\nMensaje cifrado RSA:", base64.b64encode(encrypted_symmetric_key).decode())
    print("Mensaje descifrado:", message)
    print("Tag:", base64.b64encode(tag).decode())
    print("Nonce (IV):", base64.b64encode(nonce).decode())
    print("Mensaje integro")

    # Verificar si la firma digital es válida
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(message.encode()), signature)
        print("La firma es válida.")
    except (ValueError, TypeError):
        print("La firma no es válida.")

    return jsonify({"username": username, "message": message})

@app.route("/get_messages")
def get_messages():
    global messages
    serialized_messages = []
    for message in messages:
        # Convertir los datos binarios a Base64 para serialización JSON
        serialized_message = {
            "username": message["username"],
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

@app.route("/logout", methods=['POST'])
def logout():
    global symmetric_key, private_key, public_key, messages
    symmetric_key = None
    private_key = None
    public_key = None
    messages.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
