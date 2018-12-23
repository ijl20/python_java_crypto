# Compatible AES encrypt/decrypt in Python and Java

The requirement was to be able to encrypt text in Python and decrypt it in Java, and vice versa.

We're using AES-128, with the use of standard crypto libraries and kept as simple as posssible.

In Python we're using the package `pycrypto`:
```
pip install pycrypto
```
and in the Python code:
```
from Crypto.Cipher import AES
import base64
```

In Java:
```
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
```

The source files are in the `java` and `python` directories, with the same approach for both.

The test script is `run.sh` which simply executes the Python and Java programs so you can see the
same (base64-encoded) encryption string is generated and decoded by both.

AES-128 is used, which uses a 128-bit block size (16 bytes) and similarly requires a 16-byte key and
(in our choice of options) a 16-byte 'initialization vector':

**block size** (16 bytes): AES inconveniently is defined to encrypt data in chunks of a fixed size, in this case
16 bytes.  This requires the use of *padding* i.e. if the message is shorter than an exact multiple of 16 bytes
it has to have additional bytes added until the message is an exact multiple of 16 bytes (see section below).

**key** (16 bytes): This is your super-top-secret, used for both encrypting and decrypting the message.  How
you have the sender and receiver know the same key is up to you.

**initialization vector** (16 bytes): AES is a kind of incremental roll-as-you-go algorithm where each encoded
byte depends on every byte encoded so far.  The initialization vector (iv) is kind of an agreed initial state that
gets the ball rolling before the message encryption starts and this improves the impenetrability of the 
final encryption. So long as the sender and receiver start with the same iv for a given message,
the decryption will work.  At this point the iv and the key sound pretty similar, but the 
difference is the iv need not be secret but can be changed for each message.  If the sender
changes the iv with each message then it needs to transmit the iv with the message - an easy way to do this
is to prepend the *unencrypted* iv to the encrypted message - the receiver then chops off the first 16 bytes and uses
those as the iv for the decryption of the rest of the message.

## bytes vs Strings

It is important to understand the encryption algorithm thinks of the data as a sequence of bytes, not characters.
Hence if you're passing 'Strings' around, particularly between Java and Python, you need to be able to
convert those Strings to byte arrays and vice versa. Not a problem, but you have to understand it.

An equally important issue to understand is that Strings in different systems can (will) have different
character encodings, i.e. the mapping of a String such as "Hello World" to its underlying binary representation.
Unfortunately, given the underlying binary representation it is not possible to know for sure which character
encoding was used in the String that resulted in that binary.

This means between your systems you not only have to share the super-top-secret key, you also need to share the
character encoding you are using, such as 'utf-8'.  This isn't that big a deal but it does mean your
Bytes-to-String routines will require the 'character encoding' as a parameter of the conversion.

Python3 has `String.encode('UTF-8')` for String->bytes, and `base64.b64encode(bytes)` for bytes->String.

Java has `String.getBytes("UTF-8")` and `new String(byte_array, StandardCharsets.UTF_8)`.

