"""
Demo script. Generates keys, signs a message, verifies it, and demonstrates tamper detection.
"""
from key_utils import generate_keys, save_file
from crypto_utils import sign_message, verify_message, container_to_json

def demo():
    # Generate RSA keys
    private_pem, public_pem = generate_keys(2048)
    save_file('priv_demo.pem', private_pem)
    save_file('pub_demo.pem', public_pem)

    message = b"This is a demo message for the HMAC-PRNG + RSA-PSS scheme."

    # Sign the message
    container = sign_message(message, private_pem)
    print('Signature Container:')
    print(container_to_json(container))

    # Verify (should be True)
    ok = verify_message(message, public_pem, container)
    print('\nVerification result (original):', ok)

    # Tamper the message
    tampered = b"This is a tampered message for the HMAC-PRNG + RSA-PSS scheme."
    ok2 = verify_message(tampered, public_pem, container)
    print('Verification result (tampered):', ok2)


if __name__ == '__main__':
    demo()
