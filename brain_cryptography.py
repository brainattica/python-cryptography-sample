# Python imports
import base64

# Third-Party imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.interfaces import RSAPrivateKey, RSAPublicKey
# Apps imports


class BrainCryptographyInterface(object):
    """ Inteface / Abstract Class concept for readability. """

    def generate_rsa_keypair(self, bits=2048):
        raise NotImplementedError("""Exception raised,
        BrainCryptographyInterface is supposed to be an interface / abstract class!""")

    def encrypt_message(self, public_key_loc, message):
        raise NotImplementedError("""Exception raised,
        BrainCryptographyInterface is supposed to be an interface / abstract class!""")

    def decrypt(self, private_key, package):
        raise NotImplementedError("""Exception raised,
        BrainCryptographyInterface is supposed to be an interface / abstract class!""")

    def sign_data(self, private_key, data):
        raise NotImplementedError("""Exception raised,
        BrainCryptographyInterface is supposed to be an interface / abstract class!""")

    def verify_sign(self, public_key, signature, data):
        raise NotImplementedError("""Exception raised,
        BrainCryptographyInterface is supposed to be an interface / abstract class!""")


class BrainCryptography(BrainCryptographyInterface):

    def generate_rsa_keypair(self, bits=4096):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )

    def export_private_key(self, private_key):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return pem.splitlines()

    def export_public_key(self, public_key):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return pem.splitlines()


    def load_private_key(self, private_key_pem_export):
        private_key_pem_export = (bytes(private_key_pem_export, encoding='utf8')
                                  if not isinstance(private_key_pem_export, bytes) else private_key_pem_export)

        return serialization.load_pem_private_key(
            private_key_pem_export,
            password=None,
            backend=default_backend()
        )

    def load_public_key(self, public_key_pem_export):
        public_key_pem_export = (bytes(public_key_pem_export, encoding='utf8')
                                 if not isinstance(public_key_pem_export, bytes) else public_key_pem_export)

        return serialization.load_pem_public_key(
            data=public_key_pem_export,
            backend=default_backend()
        )

    def encrypt_message(self, public_key, message):
        message = bytes(message, encoding='utf8') if not isinstance(message, bytes) else message
        public_key = public_key if isinstance(public_key, RSAPublicKey) else self.load_pem_public_key(
            public_key_pem_export=public_key
        )

        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        return str(base64.b64encode(ciphertext), encoding='utf-8')

    def decrypt(self, private_key, ciphertext):
        ciphertext = base64.b64decode(ciphertext) if not isinstance(ciphertext, bytes) else ciphertext
        private_key = private_key if isinstance(private_key, RSAPrivateKey) else self.load_pem_private_key(
            private_key_pem_export=private_key
        )

        plain_text = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return str(plain_text, encoding='utf8')

    def sign_data(self, private_key, data):
        data = bytes(data, encoding='utf8') if not isinstance(data, bytes) else data
        private_key = private_key if isinstance(private_key, RSAPrivateKey) else self.load_pem_private_key(
            private_key_pem_export=private_key
        )

        signer = private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signer.update(data)
        signature = signer.finalize()
        return str(base64.b64encode(signature), encoding='utf8')

    def verify_sign(self, public_key, signature, data):
        try:
            data = bytes(data, encoding='utf8') if not isinstance(data, bytes) else data
            signature = base64.b64decode(signature) if not isinstance(signature, bytes) else signature

            public_key = public_key if isinstance(public_key, RSAPublicKey) else self.load_pem_public_key(
                public_key_pem_export=public_key
            )

            verifier = public_key.verifier(
                signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            verifier.update(data)
            verifier.verify()
            return True

        except InvalidSignature:
            return False
