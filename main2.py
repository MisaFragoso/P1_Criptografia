# -*- coding: utf-8 -*-
"""
Created on Wed Apr  3 17:03:56 2024

@author: Escritorio
"""

from flask import Flask, render_template, request, jsonify, redirect
from Crypto.PublicKey  import  RSA


app = Flask(__name__)

messages = []
secret = None

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/chat")
def chat():
    return render_template("index.html", messages=messages)

@app.route("/login", methods=["POST"])
def login():
    global secret
    secret = request.form["secret"]
    if not secret and not request.files['private_key']:
        return redirect("/")
    elif secret and not request.files['private_key'] :
        # Generar pareja de claves RSA de 2048 bits de longitud
        key = RSA.generate(2048)
        # Exportamos la clave privada
        private_key = key.export_key(passphrase=secret)
        # Guardamos la clave privada en un fichero
        with open("private.pem", "wb") as f:
            f.write(private_key)
        # Obtenemos la clave pública
        public_key = key.publickey().export_key()
        # Guardamos la clave pública en otro fichero
        with open("public.pem", "wb") as f:
            f.write(public_key)
    # Redirigir al chat después de ingresar el secreto
    return redirect("/chat")

@app.route("/send_message", methods=["POST"])
def send_message():
    global messages
    username = request.form["username"]
    message = request.form["message"]
    messages.append({"username": username, "message": message})
    return jsonify({"username": username, "message": message})

@app.route("/get_messages")
def get_messages():
    global messages
    return jsonify({"messages": messages})

if __name__ == "__main__":
    app.run(debug=True)
