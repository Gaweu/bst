from generateRandom import generateRandom
import os.path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pss
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generateRSA():
    key = RSA.generate(2048, generateRandom)
    privKey = key.export_key()
    pubKey = key.public_key().export_key()
    with open('public_key.pub', 'wb') as f:
        f.write(pubKey)
    with open('private_key', 'wb') as f:
        f.write(privKey)
    print("Keys generated!")

def generateSign():
    with open('message.txt', 'rb') as f:
        hash = SHA512.new(f.read())

    key = RSA.import_key(open("private_key").read())
    signature = pss.new(key).sign(hash)

    with open("signature", 'wb') as f:
        f.write(signature)
        print("Signature generated!")
        print(f"Signature = {signature}")

def validateSign():
    with open('message.txt', 'rb') as f:
        hash = SHA512.new(f.read())

    with open("signature", "rb") as f:
        signature = f.read()
    
    key = RSA.import_key(open("private_key").read())
    verifier = pss.new(key)

    try: 
        verifier.verify(hash, signature)
        print("Valid signature")
    except (ValueError, TypeError):
        print("Not valid signature")

def encrypt():
    with open('message.txt', 'rb') as f:
        data = f.read()
    
    pubKey = RSA.import_key(open('public_key.pub').read())
    sessionKey = generateRandom(48)
    cipher_rsa = PKCS1_OAEP.new(pubKey)
    sessionKeyEncrypted = cipher_rsa.encrypt(sessionKey)
    cipherAes = AES.new(sessionKey, AES.MODE_EAX)
    cipherText, tag = cipherAes.encrypt_and_digest(data)
    
    with open("encrypted", "wb") as f:
        f.write(sessionKeyEncrypted)
        f.write(cipherAes.nonce)
        f.write(tag)
        f.write(cipherText)
    print("File encrypted!")

def decrypt():
    privKey = RSA.import_key(open('private_key').read())
    with open('encrypted', 'rb') as f:
        sessionKey = f.read(privKey.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        cipherText = f.read(-1)

    cipher_rsa = PKCS1_OAEP.new(privKey)
    sessionKey = cipher_rsa.decrypt(sessionKey)      

    cipher_aes = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(cipherText, tag)  
    
    with open("decrypted.txt", "wb") as f:
        f.write(data)
    print("File decrypted!")