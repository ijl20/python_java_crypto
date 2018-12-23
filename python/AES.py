from Crypto.Cipher import AES
import base64


plaintext = "The quick brown fox jumps over the lâzy dতg";
#plaintext = "1234567890ABCDEF"

key = "aesEncryptionKey".encode()  # AES-128 with 16-byte key/iv
iv =  "encryptionIntVec".encode()

def pad(byte_array):
    BLOCK_SIZE = 16
    print("pad length byte_array {0}".format(len(byte_array)))
    pad_len = BLOCK_SIZE - len(byte_array) % BLOCK_SIZE

    return byte_array + (bytes([pad_len]) * pad_len)

def unpad(byte_array):
    last_byte = byte_array[-1]
    return byte_array[0:-last_byte]

def encrypt(byte_array, iv, key):
    """
    Input bytes, return encrypted bytes, using iv and key
    """

    print("encrypt {0} bytes".format(len(byte_array)))
    print("encrypt key {0} bytes".format(len(key)))

    padded = pad(byte_array)

    print("encrypt padded {0} length {1} bytes".format(padded,len(padded)))

    # Note rather than using a fixed initialization vector, we could
    # generate a random one and prepend that to the encrypted result.
    # The recipient then needs to unpack the iv and use it.
    #iv = Random.new().read(AES.block_size);
    cipher = AES.new( key, AES.MODE_CBC, iv )
    encrypted = cipher.encrypt(padded)
    return encrypted

def decrypt(bytes_array, iv, key ):
    """
    Input encrypted bytes, return decrypted bytes, using iv and key
    """

    cipher = AES.new(key, AES.MODE_CBC, iv )

    decrypted_padded = cipher.decrypt(bytes_array)

    decrypted = unpad(decrypted_padded)

    return decrypted

print("plaintext {0}".format(plaintext))

encrypted = encrypt(plaintext.encode('utf-8'),iv,key)

print("encrypted {0}".format(base64.b64encode(encrypted)))

decrypted = decrypt(encrypted, iv, key)

print("decrypted {0}".format(decrypted.decode('utf-8')))

