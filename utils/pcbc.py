from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import secrets

BLOCK_SIZE = 16  # AES block size in bytes

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b1, b2))

def pad(data: bytes) -> bytes:
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    return padder.update(data) + padder.finalize()

def unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt_image(image: Image.Image, password: str) -> tuple[Image.Image, bytes]:
    key = derive_key(password)
    iv = secrets.token_bytes(BLOCK_SIZE)

    raw_data = image.tobytes()
    padded_data = pad(raw_data)

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    prev_cipher = iv
    prev_plain = b'\x00' * BLOCK_SIZE
    ciphertext = b""

    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i+BLOCK_SIZE]
        xor_input = xor_bytes(block, xor_bytes(prev_cipher, prev_plain))
        encrypted_block = encryptor.update(xor_input)

        ciphertext += encrypted_block
        prev_plain = block
        prev_cipher = encrypted_block

    final_data = iv + ciphertext
    preview = Image.frombytes(image.mode, image.size, padded_data[:len(image.tobytes())])
    return preview, final_data

def decrypt_image(data: bytes, password: str, size: tuple[int, int], mode: str) -> Image.Image:
    key = derive_key(password)
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    prev_cipher = iv
    prev_plain = b'\x00' * BLOCK_SIZE
    plaintext = b""

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        decrypted = decryptor.update(block)
        plain_block = xor_bytes(decrypted, xor_bytes(prev_cipher, prev_plain))

        plaintext += plain_block
        prev_plain = plain_block
        prev_cipher = block

    unpadded = unpad(plaintext)
    return Image.frombytes(mode, size, unpadded)
