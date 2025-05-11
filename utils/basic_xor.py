from PIL import Image

def crypt(img: Image.Image, key: int) -> Image.Image:
    # Convert image to raw byte data
    imgdata = img.convert("RGB")
    image_bytes = bytearray(imgdata.tobytes())

    # XOR each byte with the key
    for index in range(len(image_bytes)):
        image_bytes[index] ^= key

    # Recreate the image from the modified bytes
    encrypted_img = Image.frombytes("RGB", imgdata.size, bytes(image_bytes))
    return encrypted_img
