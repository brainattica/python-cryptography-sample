# Python imports
import unittest
# Django Core imports

# Third-Party imports

# Apps imports
from brain_cryptography import BrainCryptography
from cryptography.hazmat.backends.openssl.rsa import _RSAPrivateKey, _RSAPublicKey


class BrainCryptographyTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.brain_crypto_handler = BrainCryptography()
        cls.message = "Code must be like a piece of music"
        cls.private_key = cls.brain_crypto_handler.generate_rsa_keypair()

    def setUp(self):
        pass

    def test_generate_rsa_keypair(self):
        private_key = self.brain_crypto_handler.generate_rsa_keypair()
        self.assertTrue(isinstance(private_key, _RSAPrivateKey))
        self.assertTrue(isinstance(private_key.public_key(), _RSAPublicKey))

    def test_export_private_key(self):
        pem_private_key = self.brain_crypto_handler.export_private_key(private_key=self.private_key)
        self.assertTrue('-----BEGIN RSA PRIVATE KEY-----' in str(pem_private_key[0], encoding='utf8'))

    def test_export_public_key(self):
        pem_public_key = self.brain_crypto_handler.export_public_key(public_key=self.private_key.public_key())
        self.assertTrue('-----BEGIN PUBLIC KEY-----' in str(pem_public_key[0], encoding='utf8'))

    def test_load_pem_private_key(self):
        pem_private_key = self.brain_crypto_handler.export_private_key(private_key=self.private_key)
        pem_private_key_bytes = b'\n'.join(pem_private_key)
        private_key = self.brain_crypto_handler.load_private_key(private_key_pem_export=pem_private_key_bytes)
        self.assertTrue(isinstance(private_key, _RSAPrivateKey))

    def test_load_pem_public_key(self):
        pem_public_key = self.brain_crypto_handler.export_public_key(public_key=self.private_key.public_key())
        pem_public_key_bytes = b'\n'.join(pem_public_key)
        public_key = self.brain_crypto_handler.load_public_key(public_key_pem_export=pem_public_key_bytes)
        self.assertTrue(isinstance(public_key, _RSAPublicKey))

    def test_encrypt_and_decrypt_message(self):
        sender_private_key = self.brain_crypto_handler.generate_rsa_keypair()
        recipient_private_key = self.brain_crypto_handler.generate_rsa_keypair()
        

        ciphertext = self.brain_crypto_handler.encrypt_message(
            public_key=recipient_private_key.public_key(),
            message=self.message
        )

        signature = self.brain_crypto_handler.sign_data(
            private_key=sender_private_key,
            data=self.message
        )

        plain_text = self.brain_crypto_handler.decrypt(
            private_key=recipient_private_key,
            ciphertext=ciphertext
        )

        self.assertNotEqual(self.message, ciphertext)
        self.assertEqual(self.message, plain_text)
        self.assertTrue(self.brain_crypto_handler.verify_sign(
            public_key=sender_private_key.public_key(),
            signature=signature,
            data=plain_text
        ))



if __name__ == '__main__':
    unittest.main()
