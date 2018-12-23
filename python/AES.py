from Crypto.Cipher import AES
from Crypto import Random
import base64

BS = 16
#pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

plaintext = "The quick brown fox jumps over the lâzy dতg";

key = "aesEncryptionKey".encode()
iv =  "encryptionIntVec".encode()

def utf8len(s):
    return len(s.encode('utf-8'))

def pad(byte_array):
    print("pad length byte_array {0}".format(len(byte_array)))
    pad_len = BS - len(byte_array) % BS

    pad_chr = chr(pad_len)

    pad_str = pad_len * pad_chr

    return byte_array + bytes(pad_str.encode('utf-8'))

def encrypt(s):
    """
    Returns hex encoded encrypted value!
    """

    print("encrypt input length {0} chars".format(len(s)))

    raw = bytes(s.encode('utf-8'))

    print("encrypt input length {0} bytes".format(len(raw)))
    print("encrypt key length {0} bytes".format(len(key)))

    raw = pad(raw)

    print("encrypt padded length {0} bytes".format(len(raw)))

    #iv = Random.new().read(AES.block_size);
    cipher = AES.new( key, AES.MODE_CBC, iv )
    encrypted = cipher.encrypt(raw)
    return encrypted

def decrypt( enc ):
    """
    Requires hex encoded param to decrypt
    """
    enc = enc.decode("hex")
    iv = enc[:16]
    enc= enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc))

#    key = "140b41b22a29beb4061bda66b6747e14"
#    ciphertext = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
#    key=key[:32]
#    decryptor = AESCipher(key)
#    plaintext = decryptor.decrypt(ciphertext)
#    print "%s" % plaintext

print("plaintext {0}".format(plaintext))

enc = encrypt(plaintext)

print("encrypted {0}".format(base64.b64encode(enc)))

dec = decrypt

