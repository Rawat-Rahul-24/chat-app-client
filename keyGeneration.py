from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
import os
import json

curve = registry.get_curve('brainpoolP256r1')

def generate_ecc_keys():
    global private_key, public_key
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g


def readFile(path):
    """ Reads a file from the given path and returns data in byte array format. Returns None if file does not exist."""
    try:
        file = open(path, mode="rb")
        content = file.read()
        file.close()
        return content
    except:
        return None

def writeFile(path, content, parentFolder="downloads"):
    """ Writes the content in a file on the given path. If path does not exist, makes a new directory. """
    path = os.path.join(parentFolder, path)
    if not os.path.exists(path.rsplit("\\", 1)[0]):
        os.mkdir(path.rsplit("\\", 1)[0])
    origPath = path.rsplit(".")
    count = 1
    while os.path.exists(path):
        path = origPath[0] + " (" + str(count) + ")." + origPath[1]
        count += 1
    file = open(path, mode="wb")
    file.write(content)
    file.close()

def readJSONFile(path):
    """ Reads a JSON file from the given path. Returns None if file does not exist."""
    try:
        file = open(path + ".json", "r")
        data = json.loads(file.read())
        file.close()
        return data
    except:
        return None

def writeJSONFile(path, content):
    """ Writes a JSON file to the given path with the given content. """
    with open(path + ".json", "w") as file:
        json.dump(content, file)
        file.close()


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()



def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

def checkWorking():
    msg = b'Text to be encrypted by ECC public key and ' \
          b'decrypted by its corresponding ECC private key'
    print("original msg:", msg)
    print("public key:", public_key)
    encryptedMsg = encrypt_ECC(msg, public_key)
    encryptedMsgObj = {
        'ciphertext': binascii.hexlify(encryptedMsg[0]),
        'nonce': binascii.hexlify(encryptedMsg[1]),
        'authTag': binascii.hexlify(encryptedMsg[2]),
        'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    }
    print("encrypted msg:", encryptedMsgObj)

    decryptedMsg = decrypt_ECC(encryptedMsg, private_key)
    print("decrypted msg:", decryptedMsg)

def receivePackets(socket, size=4096):
    """ Receives all incoming packets from the socket until the end of the message. """
    data = socket.recv(size).split(b" ", 1)
    dataSize = int(data[0].decode())
    data = data[1]
    while len(data) != dataSize:
        data += socket.recv(size if dataSize - len(data) >= size else dataSize - len(data))
    return data

def sendPackets(socket, message):
    """ Sends a message to a socket. Adds the length of the message at the beginning. """
    socket.sendall(str(len(message)).encode("utf-8") + b" " + message)

def encrypt(msg):
    return encrypt_ECC(msg, public_key)

def decrypt(msg):
    return decrypt_ECC(msg, private_key)


if __name__ == "__main__":
    # Example usage
    generate_ecc_keys()
    checkWorking()