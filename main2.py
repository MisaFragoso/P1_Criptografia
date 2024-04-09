# -*- coding: utf-8 -*-
"""
Created on Wed Apr  3 17:03:56 2024

@author: Escritorio
"""

from flask import Flask, render_template, request, jsonify, redirect, send_file
#liberirias para RSA
from Crypto.PublicKey import RSA


#librerias para cifrado y decifrado AES con modo de cifrado GCM

from Crypto.Random import get_random_bytes

#liberirias para pbkdf
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import os

app = Flask(__name__)

messages = []
secret = None
sesion=0  #  sesión
nameus="jorge"
k_priu1="hola"
k_priu2="hola"

@app.route("/")
def index():
   global k_priu1
   if sesion==1:  # Si ya existe una sala de chat en la sesión, redirige al chat
      
       return redirect("/user2")
   else:  # Si no hay una sala de chat en la sesión, redirige a la página de login
        return render_template("login.html")

@app.route("/chat")
def chat():
     global k_priu2
     if sesion==0: # Si no hay una sala de chat en la sesión, redirige al usuario a la página de inicio de chat
        return redirect("/")
     else:
      
        return render_template("index.html", messages=messages)

@app.route("/login", methods=["POST"])
def login():
    global secret, sesion,contrasena
    secret = request.form["secret"]
    key_location = request.form["key_location"]
    sesion=1
   
    if not secret and not request.files['private_key']: 
        return redirect("/")
    if secret and not request.files['private_key'] :
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
        return render_template("login.html")
    elif request.files['private_key']:
        
        #Generamos llave/clave simetrica
           contrasena=bytes(secret, 'utf-8')
           longitud_clave = 32 #32 bytes o 256 bits
           salt = get_random_bytes(16) #salt de 16 bytes o 128 bits  bytes: El valor de salt aleatorio.
           clave_simetrica = pbkdf(contrasena, salt, longitud_clave)
           print("Salt generado:", salt.hex())
           print("Clave simétrica derivada:", clave_simetrica.hex())
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

@app.route("/user2")
def user2():
  return render_template("login.html")


@app.route("/logout",  methods=['POST'])
def logout():
    # Limpiar todos los mensajes de la sesión
    messages.clear()
    # Redirigir a la página de inicio de sesión
    sesion=0 #evita regresar y ver los mensajes de chats previos
    return redirect("/")

#Funcion generadora del pbkdf mediante sha256
def pbkdf(contrasena, salt, longitud_clave):
  kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=longitud_clave,
        salt=salt,
        iterations= 100000,
        backend=default_backend() # Backend por defecto
        ) 
  return kdf.derive(contrasena)


if __name__ == "__main__":
    app.run(debug=True)
