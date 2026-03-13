# pip3 install pycryptodome for AES encryption,
# padding, SHA256, and MAC verification

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC

# Generates Public Key of User 1 and User 2
def generate_public_key(private_key, g, p):
    return pow(g,private_key,p)

# Generates Shared Key of User 1 and User 2
def generate_shared_key(other_user_public_key, private_key, p):
    return pow(other_user_public_key, private_key, p)

# Adding bytes to the shared key, so that it can be used in AES encryption.
def derive_key(shared_key):
    h = SHA256.new()
    h.update(str(shared_key).encode())
    return h.digest()

# Encryptes the message
def encrypt_text(message, key):
    # Uses AES to encrypt message.
    cipher = AES.new(key,AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    C =  cipher.iv + ciphertext

    # HMAC the C
    h = HMAC.new(key,C, digestmod = SHA256)
    mac = h.digest()

    # Hash the HMAC
    H = SHA256.new(mac).digest()
    return C, H

# Decryptes the text
def decrypt_text(C, H, key):
    iv = C[0:16]
    ciphertext = C[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message =  unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    # Recomupute the C
    h = HMAC.new(key,C, digestmod = SHA256)
    mac = h.digest()

    # Hash the HMAC
    computed_H = SHA256.new(mac).digest()

    # Check if re-computed H matches with H sent to us
    if computed_H == H:
        print("Message Verified")
        return message
    else:
        print("Integrity Failed")
        return None