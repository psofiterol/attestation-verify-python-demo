import json

from eth_account import Account
from web3 import Web3
from eth_keys import keys
from eth_utils import decode_hex


def compute_msg_hash(sign_params: str)->bytes:
    # 1. keccak256 of the message (as bytes)
    message_hash = "0x"+Web3.keccak(text=sign_params).hex()
    # print("hash:", message_hash)
    prefix = "\u0019Ethereum Signed Message:\n" + str(len(message_hash))
    to_sign = (prefix + message_hash).encode("utf-8")
    msg_hash = Web3.keccak(to_sign)
    # print("msgHash:", msg_hash.hex())
    return msg_hash

def sign_message(app_secret: str, sign_params: str) -> str:
    msg_hash = compute_msg_hash(sign_params)
    pk = keys.PrivateKey(decode_hex(app_secret))
    signature = pk.sign_msg_hash(msg_hash)
    return signature.to_bytes().hex()


def verify_signature(sign_params: str, signature: str) -> str:
    msg_hash = compute_msg_hash(sign_params)
    # log msg_hash
    print("msgHash:", msg_hash.hex())
    sig_bytes = bytes.fromhex(signature[2:] if signature.startswith('0x') else signature)
    sig_obj = keys.Signature(sig_bytes)
    pk = keys.ecdsa_recover(msg_hash, sig_obj)
    return pk.to_checksum_address()


if __name__ == '__main__':
    # Example usage
    # Replace with your own app secret, this key just for test: appId->0x811169961c2949e8c91e7840c5452cc4deb1942c
    appSecret = "0xafa01caf44f07d2b21bc5e2bde1de2a8ba56f33ac2e223169f99634f57d049b5"
    # !!!Notice: sign_params is a string not object
    # sign_params = "{\"appId\":\"0x811169961c2949e8c91e7840c5452cc4deb1942c\",\"attTemplateID\":\"2e3160ae-8b1e-45e3-8c59-426366278b9d\",\"userAddress\":\"0xB12a1f7035FdCBB4cC5Fa102C01346BD45439Adf\",\"timestamp\":1752730452083,\"attMode\":{\"algorithmType\":\"proxytls\",\"resultType\":\"plain\"}}"
    sign_params = {"appId":"0x17ae11d76b72792478d7b7bcdc76da9574ab3cf8","attTemplateID":"369e1db8-47c9-4dc6-85b5-037cd02d3383","userAddress":"0x7ab44DE0156925fe0c24482a2cDe48C465e47573","timestamp":1752746994843,"attMode":{"algorithmType":"proxytls","resultType":"plain"},"requestid":"89cfef86-c272-410e-b66e-f38d67916852","backUrl":"","computeMode":"nonecomplete"}
    print("sign_params:", sign_params)
    sig = sign_message(appSecret, json.dumps(sign_params))
    print("Signature:", "0x"+sig)
    recovered = verify_signature(json.dumps(sign_params), sig)
    print("Recovered appId:", recovered)
    signedRequestStr = {
        "attRequest": sign_params,
        "appSignature": "0x"+sig
    }
    print("signedRequestStr:", signedRequestStr)
