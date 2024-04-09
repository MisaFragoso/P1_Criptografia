# -*- coding: utf-8 -*-
"""
Created on Mon Apr  8 12:22:06 2024

@author: Albert GP Pérez
"""
#liberirias para RSA
#from Crypto.PublicKey import RSA as CryptoRSA
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#librerias para cifrado y decifrado AES con modo de cifrado GCM
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#liberirias para pbkdf, hasheo y firma
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


#funcion pbkdf con base en el secreto/contraseña ingresado por el usuario
def derivar_clave_simetrica(contrasena, salt, longitud_clave):
  kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=longitud_clave,
        salt=salt,
        iterations= 100000,
        backend=default_backend() # Backend por defecto
        ) 
  return kdf.derive(contrasena) #genera la llave simetrica


##########################################################
#Establecer clave, generar llaves asimetricas con RSA
#Mediante el salt se crea la clave simetrica
#Llave simetrica se usa para enviar los mensajes
#Llaves asimetrica se usa para enviar la clave simetrica
#########################################################
  
secret = 'HOLA'
contrasena = bytes(secret, 'utf-8') #tranformación del contenido de secret a bytes
longitud_clave = 32 #32 bytes o 256 bits

#Genracion llaves asimetricas con RSA 
#(debe existir una funcion para us1 y para us2, aqui solo esta la del usuario 1)
#clave = CryptoRSA.generate(2048)
# Exportamos la clave privada
#private_key = clave.export_key()
# Obtenemos la clave pública
#public_key = clave.publickey().export_key()
# Convertir las claves de bytes a cadenas de texto

# Generar un par de claves RSA para el firmante
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serializar las claves en formato PEM
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Imprimir las claves en formato PEM
print("Clave privada RSA:")
print(private_key_pem.decode())

print("\nClave pública RSA:")
print(public_key_pem.decode())

#clave_privada_str = private_key.decode('utf-8')
#clave_publica_str = public_key.decode('utf-8')

# Imprimir las claves
#print("Clave privada RSA:")
#print(clave_privada_str)
#print("\nClave pública RSA:")
#print(clave_publica_str)


#salt de 16 bytes o 128 bits  bytes: El valor de salt aleatorio.
salt = get_random_bytes(16)
print("Salt generado:", salt.hex())
#clave simetrica generada mediante pbkdf usando el secreto (contrasena) del usaurio
clave_simetrica = derivar_clave_simetrica(contrasena, salt, longitud_clave)
print("Clave simétrica derivada:", clave_simetrica.hex())


################################################
#Cifrado y Decifrado mediante RSA
###############################################

# Crear un objeto cifrador RSA utilizando el esquema PKCS#1 OAEP
#cifrador_rsa = PKCS1_OAEP.new(clave)
#Llave simetrica-cifrado RSA
#mensaje_cifrado = cifrador_rsa.encrypt(clave_simetrica) 
#print("Mensaje cifrado RSA:", mensaje_cifrado.hex())

# Cifrar el mensaje con la clave pública RSA
cifrador = public_key.encrypt(
    clave_simetrica,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Mensaje cifrado RSA:", cifrador.hex())

# Crear un objeto descifrador RSA utilizando la misma clave
#descifrador_rsa = PKCS1_OAEP.new(clave)
#llave simetrica-decifrada
#mensaje_descifrado = descifrador_rsa.decrypt(mensaje_cifrado)

# Descifrar el mensaje cifrado con la clave privada RSA
mensaje_descifrado = private_key.decrypt(
    cifrador,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Mensaje descifrado:", mensaje_descifrado.hex())


################################################
#Cifrado y Decifrado mediante AES
###############################################

# Función para cifrar un mensaje usando AES-256

 # Generar un vector de inicialización (IV) aleatorio
iv = get_random_bytes(12)  # IV debe tener 12 bytes para GCM

# Mensaje a cifrar
msg= "Hola, este es un mensaje secreto"
mensaje = bytes(msg, 'utf-8')
print(msg)

# Crear un objeto cifrador AES en modo GCM
cifrador_aes = AES.new(clave_simetrica, AES.MODE_GCM, nonce=iv)
    # Cifrar el mensaje utilizando AES en modo GCM
mensaje_cifrado, tag = cifrador_aes.encrypt_and_digest(mensaje)

print("Mensaje cifrado:", mensaje_cifrado.hex())
print("Tag:", tag.hex()) # para verificar la autenticidad del mensaje
print("Nonce (IV):", iv.hex())

# Crear un objeto cifrador AES en modo GCM
cifrador_aes2 = AES.new(clave_simetrica, AES.MODE_GCM, iv)
# Descifrar el mensaje
# Establecer el tag recibido, decrypt() can only be called after initialization or an update()
cifrador_aes2.update(tag)
mensaje_descifrado = cifrador_aes2.decrypt(mensaje_cifrado)
print("Mensaje descifrado:", mensaje_descifrado.decode('utf-8'))

###############################################
#HASHEO-Hash2 512
###############################################

# Crear un objeto de hash SHA-512
hash_512 = hashes.Hash(hashes.SHA512(), backend=default_backend())

# Actualizar el hash con el mensaje cifrado con AES
hash_512.update(mensaje_cifrado)

# Obtener el resultado del hash
hash_value = hash_512.finalize()

print("Hash SHA2-512:", hash_value.hex())

###############################################
#Firma Digital
###############################################
# Firmar el mensaje
firma = private_key.sign(
    hash_value,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Firma digital:", firma.hex())

# Verificar la firma
try:
    public_key.verify(
        firma,
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("La firma es válida.")
    
except:
    print("La firma no es válida.")


##############################################################################################
#Ejemplo:
# Se cifra otro mensaje igual/diferente con AES para que, 
#al sacarle hash se imprima en pantalla si es el mismo o no
##############################################################################################

# Mensaje a cifrar diferente con un espacio extra
msg= "Hola, este es un mensaje secreto"
mensaje = bytes(msg, 'utf-8')
#Vector inicial iv debe ser el mismo que se usó para cifrar

# Crear un objeto cifrador AES en modo GCM
cifrador_aes = AES.new(clave_simetrica, AES.MODE_GCM, nonce=iv)
    # Cifrar el mensaje utilizando AES en modo GCM
mensaje_cifrado, tag = cifrador_aes.encrypt_and_digest(mensaje)

print("Mensaje cifrado:", mensaje_cifrado.hex())

hash_512 = hashes.Hash(hashes.SHA512(), backend=default_backend())

# Actualizar el hash con el mensaje cifrado con AES
hash_512.update(mensaje_cifrado)

# Obtener el resultado del hash
hash_value2 = hash_512.finalize()

print("Hash SHA2-512:", hash_value.hex())

if hash_value==hash_value2:
    print("Mensaje integro")
else:
    print("mensaje modificado, integridad comprometida")