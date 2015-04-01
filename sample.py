# Python imports

# Third-Party imports

# Apps imports
from brain_cryptography import BrainCryptography


class CryptographyExample(object):

    def __init__(self):
        self.brain_crypto_handler = BrainCryptography()
        self.brain_private_key = self.brain_crypto_handler.generate_rsa_keypair(bits=2048)
        self.attica_private_key = self.brain_crypto_handler.generate_rsa_keypair(bits=2048)

    def brain_side(self):
        message = "Code must be like a piece of music"
        ciphertext = self.brain_crypto_handler.encrypt_message(
            public_key=self.attica_private_key.public_key(),
            message=message
        )
        signature = self.brain_crypto_handler.sign_data(
            private_key=self.brain_private_key,
            data=message
        )

        return (ciphertext, signature)

    def attica_side(self, message_encrypted, signature):
        plain_text = self.brain_crypto_handler.decrypt(
            private_key=self.attica_private_key,
            ciphertext=message_encrypted
        )

        if self.brain_crypto_handler.verify_sign(
            public_key=self.brain_private_key.public_key(),
                signature=signature, data=plain_text):

            return "I get it!!"

        return "Who are you!???? Signature is invalid!!!"


if __name__ == '__main__':
    crypto_example = CryptographyExample()
    brain_message, brain_signature = crypto_example.brain_side()
    print(crypto_example.attica_side(
        message_encrypted=brain_message,
        signature=brain_signature
    ))
