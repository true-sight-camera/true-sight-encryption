import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from binascii import hexlify, unhexlify
from imaging.png import PngInteractor

# Constants
IMAGE_FILE_NAME = "data/image2.png"
OUTPUT_FILE_NAME = "outputs/test1.png"
PRIVATE_KEY_FILE_NAME = "capstone"
PUBLIC_KEY_FILE_NAME = "capstone.pub"

def load_private_key(file_path: str) -> rsa.RSAPrivateKey:
    """Load an RSA private key from a PEM file."""
    try:
        with open(file_path, 'r') as key_file:
            pem_data = key_file.read()
            private_key_bytes = pem_data.encode("utf-8")
            private_key: rsa.RSAPrivateKey = load_pem_private_key(private_key_bytes, None)
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Not an RSA private key")
            return private_key
    except Exception as e:
        raise Exception(f"Error reading private key file: {str(e)}")

def load_public_key(file_path: str) -> rsa.RSAPublicKey:
    """Load an RSA public key from a PEM file."""
    try:
        with open(file_path, 'rb') as key_file:
            pem_data = key_file.read()
            public_key = load_pem_public_key(pem_data)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Not an RSA public key")
            return public_key
    except Exception as e:
        raise Exception(f"Error reading public key file: {str(e)}")

def sign_message(private_key: rsa.RSAPrivateKey, message: bytes, prehashed = True) -> bytes:
    """Sign a message using the private key."""
    try:
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256()) if prehashed else hashes.SHA256()
        )
        return signature
    except Exception as e:
        raise Exception(f"Error signing message: {str(e)}")

def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes, prehashed = True) -> bool:
    """Verify a signature using the public key."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            Prehashed(hashes.SHA256()) if prehashed else hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification error: {str(e)}")
        return False

def hash_image_sha256(data: bytes) -> bytes:
    """Create SHA256 hash of image data."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.digest()

def main():
    try:
        # Create PNG interactor for the input image
        png_creation_interactor = PngInteractor(IMAGE_FILE_NAME)

        username = "nrazee"
        png_creation_interactor.add_text_chunk_to_data("Username", username, OUTPUT_FILE_NAME)
        print("Username added to metadata")
        
        '''
        # Flatten the image and get its bytes
        image_bytes, _ = png_creation_interactor.flatten_image()
        
        # Ensure image_bytes is bytes, not a buffer
        if not isinstance(image_bytes, bytes):
            image_bytes = bytes(image_bytes)
        ''' 

        # Hash the image
        image_hash = hash_image_sha256(png_creation_interactor.image_bytes)
        print(f"Image hash (bytes): {image_hash}")
        print(f"Image hash (hex): {hexlify(image_hash).decode()}")
        print(f"Image hash (bytes array): {list(image_hash)}")

        # message = "capstone"
        # print('practice hash ',hexlify(hash_image_sha256(message.encode('utf-8'))).decode())


        # Load private key and sign the hash
        private_key = load_private_key(PRIVATE_KEY_FILE_NAME)
        signed_bytes = sign_message(private_key, image_hash)  # Pass bytes directly
        print(f"SIGNED MESSAGE: {hexlify(signed_bytes).decode()}\n")

        # compare trimmed png from frontend here

        trimmed_png = PngInteractor('trimmedPNG.png')

        if trimmed_png.image_bytes != png_creation_interactor.image_bytes:
            print(hexlify(trimmed_png.image_bytes[:20]).decode())
            print(hexlify(trimmed_png.image_bytes[-20:]).decode())
            print("original",hexlify(png_creation_interactor.image_bytes[:20]).decode())
            print(hexlify(png_creation_interactor.image_bytes[-20:]).decode())
            raise Exception("trimmed image doesn't match pre signature")
        else:
            flattened_bytes, _ = trimmed_png.flatten_image()
            print(hexlify(hash_image_sha256(flattened_bytes)).decode())
            print(len(trimmed_png.image_bytes))
            print(len(png_creation_interactor.image_bytes))

        print("trimmed images match")

        # print("")

        # print(hexlify(png_creation_interactor.image_bytes).decode())

        # print("")


        # Add signature to image metadata
        png_creation_interactor.add_text_chunk_to_data(
            "Signature", 
            hexlify(signed_bytes).decode(), 
            OUTPUT_FILE_NAME
        )
        print("Signature added to file metadata")


        print("\n-----------READING METADATA-----------\n")

        
        # Read and verify the signature
        png_reader_interactor = PngInteractor(OUTPUT_FILE_NAME)
        png_reader_interactor.read_all_metadata()

        signature = png_reader_interactor.find_signature_metadata()
        if not signature:
            raise Exception("Could not find signature in metadata")

        signature_bytes = unhexlify(signature)

        # Load public key and verify signature
        public_key = load_public_key(PUBLIC_KEY_FILE_NAME)
        
        # Print verification data for debugging
        print(f"\nVerifying signature using the following data:")
        print(f"Original hash: {hexlify(image_hash).decode()}")
        print(f"Signature: {hexlify(signature_bytes).decode()}")
        
        if verify_signature(public_key, image_hash, signature_bytes):
            print("\nSignature Verified ✓")
        else:
            print("\nSignature Verification Failed ✗")


        username_bytes = bytes(username, encoding="ascii")

        username_signature = sign_message(private_key,username_bytes, False)

        print("\nUsername: ", username)
        print("Username signature (put in request): ", hexlify(username_signature).decode())

        if verify_signature(public_key, username_bytes, username_signature, False):
            print("Username verified")
        else:
            print("Username not verified")


    except Exception as e:
        print(f"Error: {str(e)}")
        return

if __name__ == "__main__":
    main()