import io
from utils import cbc, basic_xor, ecb, pcbc, cfb
import secrets
import streamlit as st
import uuid
from PIL import Image

st.title('NKrypTor')
st.header('A Demo Website for Encrypting Images Using Various Algorithms')

options_tuple = (
    "Basic XOR Encryption",
    "Electronic CodeBook Mode",
    "Cipher Block Chaining",
    "Propagating Cipher Block Chaining",
    "Cipher Feedback Mode"
)

def generate_password(used_for:str)-> str | int:
    if used_for == options_tuple[0]:
        password = secrets.randbelow(256)
        return password
    password = secrets.token_urlsafe(8)
    return password

@st.fragment
def download_password(password:str | int) :
    unique_id = str(uuid.uuid4())
    st.download_button(
        label="Download password for Recovery",
        data=password if type(password) == str else str(password),
        file_name=f"Recovery-Password{unique_id}.txt",
        icon=":material/download:",
        key=unique_id,
        mime="text/plain"
    )

@st.fragment
def download_encrypted_data(encrypted_data):
    unique_id = str(uuid.uuid4())
    st.download_button(
        label="Download Encrypted File",
        type="primary",
        data=encrypted_data,
        key=unique_id,
        icon=":material/download:",
        file_name=f"encrypted_image{unique_id}.enc",
        mime="application/octet-stream"
    )

# @st.fragment
# def download_image(image:Image.Image, filename:str) :
    # st.download_button(
        # label="Download Image",
        # type="primary",
        # data=io.BytesIO(image.tobytes()),
        # file_name=filename,
        # mime="image/png",
        # icon=":material/download:",
    # )

def decrypt_image(encrypted_data: bytes, password: str, mode: str, img_size=None, img_mode=None):
    if mode == "Electronic CodeBook Mode":
        return ecb.decrypt_image(encrypted_data, password)
    elif mode == "Cipher Block Chaining":
        return cbc.decrypt_image(encrypted_data, password)
    elif mode == "Propagating Cipher Block Chaining":
        if img_size is None or img_mode is None:
            raise ValueError("Image size and mode must be provided for PCBC decryption.")
        return pcbc.decrypt_image(encrypted_data, password, img_size, img_mode)
    elif mode == "Cipher Feedback Mode":
        return cfb.decrypt_image(encrypted_data, password)
    else:
        raise ValueError("Unsupported decryption mode.")


def decrypt_previously_encrypted_image():
    st.subheader('Decrypt an image previously encrypted using NKrypTor')

    option = st.selectbox("Choose the correct Algorithm used to encrypt the image", options_tuple, index=None)
    st.warning("☢️ \nIf you encrypted the image using a different algorithm, the decrypted image will be corrupted.")

    img_size = None
    img_mode = None
    upload_types = ["enc"] if option != "Basic XOR Encryption" else ["jpg", "enc", "jpeg", "png", "gif"]

    # Only show additional PCBC inputs if selected
    if option == "Propagating Cipher Block Chaining":
        width = st.number_input("Original image width", min_value=1, step=1)
        height = st.number_input("Original image height", min_value=1, step=1)
        img_mode = st.selectbox("Original image mode", ["RGBA", "L", "RGB", "CMYK"])
        if width and height and img_mode:
            img_size = (int(width), int(height))

    password = st.text_input("Enter the secret password previously used to encrypt the image", type="password")
    uploadedFile = st.file_uploader("Upload the encrypted image or data file", type=upload_types)
    buttonpressed = st.button("Decrypt", type="primary")

    if password and uploadedFile and option and buttonpressed:
        try:
            if option == "Basic XOR Encryption":
                encrypted_image = Image.open(io.BytesIO(uploadedFile.read()))
                # encrypted_image = encrypted_image.convert("RGBA")  # Force a consistent mode
                decrypted_image = basic_xor.crypt(encrypted_image, int(password))
            else:
                encrypted_data = uploadedFile.read()
                decrypted_image = decrypt_image(
                    encrypted_data,
                    password,
                    option,
                    img_size=img_size,
                    img_mode=img_mode
                )

            [column] = st.columns(1,border=True)

            st.info("❗ Right click or long press on the image to download")

            with column:
                st.image(decrypted_image, caption="Decrypted Image", use_container_width=True)

        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")

def main():
    uploadedFile = st.file_uploader("Upload an image", type=["jpg", "jpeg", "png", "gif"])
    option = st.selectbox("Choose an Algorithm to apply encryption in the image", options_tuple, index=None)
    st.write("You chose to use", f"`{option}`")
    st.warning('Note ⚠️: The XOR encryption mode is purely experimental and also very weak. Don\'t use it for serious work.')
    st.text("You can generate a random password(recommended) or enter a password manually")
    st.write("Enter a password for encryption")
    password: str | int = ""
    if st.button("Generate secure random password",type="primary"):
        password = generate_password(str(option))
        st.info("To get the password input box again, reselect the encryption mode from the dropdown menu.")
    else:
        if option == options_tuple[0]:
            password = st.number_input("Enter a numeric key for encryption: Range - [0,255]",min_value=0,max_value=255)
        else:
            password = st.text_input("Enter a password for encryption", type="password")

    col1, col2, col3 = st.columns(3, border=True)

    if uploadedFile and option and password:
        st.info("❗ Right click or long press on the image to download")
        original_image = Image.open(uploadedFile).copy()
        with col1:
            st.image(original_image, caption="Original Image", use_container_width=True)

        try:
            if option == options_tuple[0]:  # Basic XOR
                encrypted_image = basic_xor.crypt(original_image, int(password))
                with col2:
                    st.image(encrypted_image, caption="Encrypted Image", use_container_width=True)
                decrypted_image = basic_xor.crypt(encrypted_image, int(password))
                with col3:
                    st.image(decrypted_image, caption="Decrypted Image", use_container_width=True)

            elif option == options_tuple[1]:  # ECB
                _, encrypted_bytes = ecb.encrypt_image(original_image, str(password))
                with col2:
                    st.success("Image encrypted successfully.")
                    download_encrypted_data(encrypted_bytes)
                decrypted_image = ecb.decrypt_image(encrypted_bytes, str(password))
                with col3:
                    st.image(decrypted_image, caption="Decrypted Image", use_container_width=True)
                with st.container(height=320,border=True):
                    st.image("./assets/imgs/ECB.jpg",use_container_width=True)
                st.caption('### `Diagram for ECB MODE Encryption Algorithm`')

            elif option == options_tuple[2]:  # CBC
                encrypted_bytes = cbc.encrypt_image(original_image, str(password))

                with col2:
                    st.success("Image encrypted successfully.")
                    download_encrypted_data(encrypted_bytes)
                # Decrypt to verify round trip
                try:
                    decrypted_image = cbc.decrypt_image(encrypted_bytes, str(password))
                    with col3:
                        st.image(decrypted_image, caption="Decrypted Image", use_container_width=True)
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")

                with st.container(height=320,border=True):
                    st.image("./assets/imgs/CBC.png",use_container_width=True)
                st.caption('### `Diagram for CBC MODE Encryption Algorithm`')
            elif option == options_tuple[3]:  # PCBC
                _, encrypted_bytes = pcbc.encrypt_image(original_image, str(password))
                with col2:
                    st.success("Image encrypted successfully.")
                    download_encrypted_data(encrypted_bytes)
                try:
                    decrypted_image = pcbc.decrypt_image(
                        encrypted_bytes, str(password),
                        original_image.size, original_image.mode
                    )
                    with col3:
                        st.image(decrypted_image, caption="Decrypted Image", use_container_width=True)
                except Exception as e:
                    st.error(f"Encryption/Decryption failed: {e}")

                with st.container(height=320,border=True):
                    st.image("./assets/imgs/PCBC.png",use_container_width=True)
                st.caption('### `Diagram for PCBC MODE Encryption Algorithm`')
            elif option == options_tuple[4]:  # CFB
                _, encrypted_bytes = cfb.encrypt_image(original_image, str(password))
                with col2:
                    st.success("Image encrypted successfully.")
                    download_encrypted_data(encrypted_bytes)
                decrypted_image = cfb.decrypt_image(encrypted_bytes, str(password))
                with col3:
                    st.image(decrypted_image, caption="Decrypted Image", use_container_width=True)

                with st.container(height=320,border=True):
                    st.image("./assets/imgs/CFB.png",use_container_width=True)
                st.caption('### `Diagram for CFB MODE Encryption Algorithm`')

            password = f"password: {password}\nheight: {original_image.size[1]}\nwidth: {original_image.size[0]}\nimage_mode: {original_image.mode}" if option == "Propagating Cipher Block Chaining" else f"password: {password}"
            download_password(password)
            st.info("❗ If you want to decrypt the image again, you have to use the same password and options used to encrypt the image.")
            st.warning("⚠️ If you encrypted the image in PCBC mode, You get the height, width and color mode (for decryption) of the original image along with the password in the password download file.")
            st.html(
                "<footer style='text-align:center;bottom:1rem'>The 'Decrypted Image' is to show that the Algorithms are correct and with the right key/password the original_image can be recovered</footer>"
            )

        except Exception as e:
            st.error(f"Encryption/Decryption failed: {str(e)}")

if __name__ == "__main__":
    landing_page, decrypt_page = st.tabs(["Encryptor", "Decryptor"])

    with landing_page:
        main()

    with decrypt_page:
        decrypt_previously_encrypted_image()
