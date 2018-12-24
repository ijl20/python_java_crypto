from Crypto.Cipher import AES
import base64
import sys

plaintext = "The quick brown fox jumps over the lâzy dতg";
#plaintext = "1234567890ABCDEF"

#key = "aesEncryptionKey".encode()  # AES-128 with 16-byte key/iv
iv =  "encryptionIntVec".encode()

def pad(byte_array):
    BLOCK_SIZE = 16
    pad_len = BLOCK_SIZE - len(byte_array) % BLOCK_SIZE

    return byte_array + (bytes([pad_len]) * pad_len)

def unpad(byte_array):
    last_byte = byte_array[-1]
    return byte_array[0:-last_byte]

def encrypt(key, message):
    """
    Input bytes, return encrypted bytes, using iv and key
    """

    byte_array = message.encode("UTF-8")

    padded = pad(byte_array)

    # Note rather than using a fixed initialization vector, we could
    # generate a random one and prepend that to the encrypted result.
    # The recipient then needs to unpack the iv and use it.
    #iv = Random.new().read(AES.block_size);
    cipher = AES.new( key.encode("UTF-8"), AES.MODE_CBC, iv )
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode("UTF-8")

def decrypt(key, message):
    """
    Input encrypted bytes, return decrypted bytes, using iv and key
    """

    byte_array = base64.b64decode(message)

    cipher = AES.new(key.encode("UTF-8"), AES.MODE_CBC, iv )

    decrypted_padded = cipher.decrypt(byte_array)

    decrypted = unpad(decrypted_padded)

    return decrypted.decode("UTF-8");

def main():
    do_encrypt = False
    if sys.argv[1] == "encrypt":
        do_encrypt = True

    key = sys.argv[2]
    message = sys.argv[3]

    if do_encrypt:
        print(encrypt(key,message))
    else:
        print(decrypt(key,message))

main()

