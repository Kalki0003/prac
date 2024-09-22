
def caesar_encrypt(text, key):
    return ''.join(chr((ord(c) - (65 if c.isupper() else 97) + key) % 26 + (65 if c.isalpha() and c.isupper() else 97)) if c.isalpha() else c for c in text)

print("Encrypted text:", caesar_encrypt(input("Enter text: "), int(input("Enter key: "))))


# Monoalphabetic 

def monoalpha(text):
    key = "qwertyuiopasdfghjklzxcvbnm"
    return text.translate(str.maketrans('abcdefghijklmnopqrstuvwxyz', key))

text_input = input("Enter text to encrypt: ")

print("Encrypted text:", monoalpha(text_input))


# Rail Fence

def rail_fence1(text, key):
    fence = [''] * key
    step = 1
    row = 0
    for char in text:
        fence[row] += char
        row += step
        if row == 0 or row == key - 1:
            step = -step
    return ''.join(fence)

print(rail_fence1("HELLO", 3))


#Columnar 

def col_trans(text, key):
    return ''.join([text[i::len(key)] for i in range(len(key))])

print(col_trans(input("Enter text : ").replace(" ",""),"adcsh"))


#DES

from Crypto.Cipher import DES
from Crypto import Random

iv = Random.get_random_bytes(8)

key = b'01234567'

des1 = DES.new(key, DES.MODE_CFB, iv)
des2 = DES.new(key, DES.MODE_CFB, iv)


text = b'KEYBOARD'

cipher_text = des1.encrypt(text)
print("Encrypted message: ", cipher_text)

decrypted_text = des2.decrypt(cipher_text).decode()
print("Decrypted message: ",decrypted_text)

#AES

from Crypto.Cipher import AES
from Crypto import Random

iv = Random.get_random_bytes(16)

key = b'01234567abhsjdfj'

aes1 = AES.new(key, AES.MODE_CFB, iv)
aes2 = AES.new(key, AES.MODE_CFB, iv)


text = b'KEYBOARD'

cipher_text = aes1.encrypt(text)
print("Encrypted message: ", cipher_text)

decrypted_text = aes2.decrypt(cipher_text).decode()
print("Decrypted message: ",decrypted_text)



# RSA

import math

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    return pow(e, -1, phi)

p, q = 17, 11  
n = p * q
phi = (p - 1) * (q - 1)

e = 7
while gcd(e, phi) != 1:
    e += 1
    
d = mod_inverse(e, phi)

print(f'Public key: ({e}, {n})')
print(f'Private key: ({d}, {n})')

def encrypt(plaintext):
    return pow(plaintext, e, n)

def decrypt(ciphertext):
    return pow(ciphertext, d, n)

plaintext = 88
ciphertext = encrypt(plaintext)
decrypted_message = decrypt(ciphertext)

print(f'Plaintext: {plaintext}')
print(f'Ciphertext: {ciphertext}')
print(f'Decrypted message: {decrypted_message}')



#Deffie_Hellman

def diffie_hellman(p, g, priv):
    return pow(g, priv, p)

# Parameters
p, g = 23, 9
priv_a, priv_b = 4, 3

# Public keys
pub_a = diffie_hellman(p, g, priv_a)
pub_b = diffie_hellman(p, g, priv_b)

# Secret keys
secret_key = diffie_hellman(p, pub_b, priv_a)  # Both parties compute the same secret key

# Output
print("Secret Key:",secret_key)


#Message Digest

from hashlib import sha1
import hmac

text=b'Good Mornning'
print('Text: ', text)

key=b'hello'
print('Key: ', key)
hashed=hmac.new(key,text,sha1)
print('Hashed Value : ', hashed.digest())


#MD5

import hashlib as h

text=b'Good Mornning'
result = h.md5(text)

print("The byte equivalent of hash is : ", end="")
print(result.digest())

#HMAC - SHA1

import hashlib as h 

text = "what a great day"
x = {
     "SHA256": h.sha256,
     "SHA512": h.sha512,
     "SHA384": h.sha384,
     "SHA224": h.sha224,
     "SHA1": h.sha1     
}

for name, func in x.items():
     print(f"The hexadecimal eqivalent of {name} is : {func(text.encode()).hexdigest()}\n")
