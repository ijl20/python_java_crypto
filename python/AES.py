from Crypto.Cipher import AES
from Crypto import Random
import base64

BS = 16
#pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
#unpad = lambda s : s[0:-ord(s[-1])]

plaintext = "The quick brown fox jumps over the lâzy dতg";
#plaintext = "1234567890ABCDEF"

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

def unpad(byte_array):
    last_byte = byte_array[-1]
    return byte_array[0:-last_byte]

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
    #enc = enc.decode("hex")
    #iv = enc[:16]
    #enc= enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv )

    decrypted_padded = cipher.decrypt(enc)

    decrypted = unpad(decrypted_padded)

    return decrypted

print("plaintext {0}".format(plaintext))

encrypted = encrypt(plaintext)

print("encrypted {0}".format(base64.b64encode(encrypted)))

decrypted = decrypt(encrypted)

print("decrypted {0}".format(decrypted.decode('utf-8')))

