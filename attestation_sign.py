from dataclasses import dataclass
from typing import List
from web3 import Web3
from eth_keys import keys
from Crypto.Cipher import AES
from binascii import unhexlify
import json

class Aes128Encryptor:
    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 16:
            raise ValueError("AES-128 key must be 16 bytes.")
        self.key = key_bytes
        self.ecb_cipher = AES.new(self.key, AES.MODE_ECB)

    @staticmethod
    def from_hex(hex_key: str):
        return Aes128Encryptor(unhexlify(hex_key))

    def encrypt_block(self, input_bytes: bytes) -> bytes:
        if len(input_bytes) != 16:
            raise ValueError("ECB block encrypt requires 16 bytes input.")
        return self.ecb_cipher.encrypt(input_bytes)

    def compute_continuous_counters(self, nonce_bytes: bytes, total_length: int) -> bytes:
        result = bytearray()
        nonce_index = bytearray(4)  # start at 0x00000000

        def incr_nonce(buf: bytearray):
            for i in reversed(range(4)):
                if buf[i] == 0xFF:
                    buf[i] = 0
                else:
                    buf[i] += 1
                    break

        incr_nonce(nonce_index)  # initial increment to match JS

        while len(result) < total_length:
            incr_nonce(nonce_index)
            full_nonce = nonce_bytes + nonce_index
            encrypted = self.encrypt_block(full_nonce)
            result.extend(encrypted)

        return bytes(result[:total_length])

class TLSRecord:
    def __init__(self, ciphertext: str, nonce: str, json_block_positions):
        self.ciphertext = ciphertext  # hex string
        self.nonce = nonce            # hex string
        self.json_block_positions = json_block_positions  # list of [start, end]

class HTTPPacket:
    def __init__(self, records: list):
        self.records = records

class TLSData:
    def __init__(self, packets: list):
        self.packets = packets

    def get_full_plain_response(self, aes_key_hex: str) -> list:
        cipher = Aes128Encryptor.from_hex(aes_key_hex)
        responses = []

        for packet in self.packets:
            response = b''

            for record in packet.records:
                nonce_bytes = unhexlify(record.nonce)
                ciphertext_bytes = unhexlify(record.ciphertext)
                counters = cipher.compute_continuous_counters(nonce_bytes, len(ciphertext_bytes))
                plain_bytes = bytes([a ^ b for a, b in zip(counters, ciphertext_bytes)])
                response += plain_bytes

            try:
                decoded = response.decode('utf-8')
                responses.append(decoded)
            except UnicodeDecodeError:
                responses.append(response.hex())

        return responses



@dataclass
class AttNetworkRequest:
    url: str
    header: str
    method: str
    body: str

@dataclass
class AttNetworkResponseResolve:
    keyName: str
    parseType: str
    parsePath: str

@dataclass
class Attestor:
    attestorAddr: str
    url: str

@dataclass
class Attestation:
    recipient: str
    request: AttNetworkRequest
    reponseResolve: List[AttNetworkResponseResolve]
    data: str
    attConditions: str
    timestamp: int
    additionParams: str
    attestors: List[Attestor]
    signatures: List[str]

def encode_string_packed(s: str) -> bytes:
    return s.encode('utf-8')

def encode_bytes_packed(b: bytes) -> bytes:
    return b

def encode_req(req: AttNetworkRequest) -> str:
    hash_hex = Web3.solidity_keccak(
        ['string', 'string', 'string', 'string'],
        [req.url, req.header, req.method, req.body]
    ).hex()
    print("attNetworkRequest:", hash_hex)
    return hash_hex

def encode_rsp(resolves: List[AttNetworkResponseResolve]) -> str:
    encode_data = b''
    for resolve in resolves:
        # 1. encode DynamicBytes
        encoded_dynamic = encode_bytes_packed(encode_data)
        # 2. encode string fields
        encoded_key = encode_string_packed(resolve.keyName)
        encoded_type = encode_string_packed(resolve.parseType)
        encoded_path = encode_string_packed(resolve.parsePath)
        # 3. concatenate
        temp_encode_data = b''
        if len(encode_data) > 0:
            trimmed = encoded_dynamic[:len(encode_data)]
            temp_encode_data += trimmed
        temp_encode_data += encoded_key
        temp_encode_data += encoded_type
        temp_encode_data += encoded_path
        encode_data = temp_encode_data
    print("attNetworkResponse encodeData:", encode_data.hex())
    hash_hex = Web3.keccak(encode_data).hex()
    print("attNetworkResponse:", hash_hex)
    return hash_hex

def encode_attestation(att: Attestation) -> str:
    from eth_utils import to_canonical_address
    # 1. address
    recipient_bytes = to_canonical_address(att.recipient)
    recipient_hex = recipient_bytes.hex()
    # 2. bytes32
    req_hash = bytes.fromhex(encode_req(att.request))
    req_hash_hex = req_hash.hex()
    rsp_hash = bytes.fromhex(encode_rsp(att.reponseResolve))
    rsp_hash_hex = rsp_hash.hex()
    # 3. string
    data_bytes = att.data.encode('utf-8')
    data_hex = data_bytes.hex()
    att_conditions_bytes = att.attConditions.encode('utf-8')
    att_conditions_hex = att_conditions_bytes.hex()
    addition_params_bytes = att.additionParams.encode('utf-8')
    addition_params_hex = addition_params_bytes.hex()
    # 4. uint64
    timestamp_bytes = att.timestamp.to_bytes(8, byteorder='big')
    timestamp_hex = timestamp_bytes.hex()
    # 5. concatenate all hex strings
    packed_hex = (
        recipient_hex +
        req_hash_hex +
        rsp_hash_hex +
        data_hex +
        att_conditions_hex +
        timestamp_hex +
        addition_params_hex
    )
    # 6. add 0x prefix
    packed_hex = '0x' + packed_hex
    # 7. convert to bytes
    packed_bytes = bytes.fromhex(packed_hex[2:])
    # 8. keccak256
    encode_hash = Web3.keccak(packed_bytes).hex()
    return encode_hash

def hex_to_bytes(hex_str: str) -> bytes:
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

def recover_address(hash_hex: str, signature: str) -> str:
    sig_bytes = hex_to_bytes(signature)
    message_hash = hex_to_bytes(hash_hex)

    if len(sig_bytes) != 65:
        raise ValueError(f"Signature length is {len(sig_bytes)}, expected 65 bytes")

    r = sig_bytes[:32]
    s = sig_bytes[32:64]
    v = sig_bytes[64]

    # Convert v from 27/28 → 0/1
    if v >= 27:
        v = v - 27

    canonical_sig = r + s + bytes([v])

    sig_obj = keys.Signature(signature_bytes=canonical_sig)
    pubkey = sig_obj.recover_public_key_from_msg_hash(message_hash)
    return pubkey.to_checksum_address()


def extract_data_from_http_response(http_response: str):
    # Split headers and body
    split_parts = http_response.split("\r\n\r\n")
    if len(split_parts) == 1:
        split_parts = http_response.split("\n\n")

    raw_json_body = split_parts[-1].strip()

    try:
        parsed = json.loads(raw_json_body)
        if "data" not in parsed:
            raise ValueError("'data' field not found in response JSON.")
        return parsed["data"]
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON body: {e}")


def main():
    # Read attestation from json file (will be passed from the FE)
    with open('attestation_binance.json', 'r', encoding='utf-8') as f:
        attestation_dict = json.load(f)
    # The aesKey (will be passed from the FE)
    aes_key="cf61e11b13d4456d715eac25b71e068f"

    # convert to object
    request = AttNetworkRequest(**attestation_dict['request'])
    reponse_resolve = [AttNetworkResponseResolve(**r) for r in attestation_dict['reponseResolve']]
    attestors = [Attestor(**a) for a in attestation_dict.get('attestors', [])]
    attestation = Attestation(
        recipient=attestation_dict['recipient'],
        request=request,
        reponseResolve=reponse_resolve,
        data=attestation_dict['data'],
        attConditions=attestation_dict['attConditions'],
        timestamp=attestation_dict['timestamp'],
        additionParams=attestation_dict['additionParams'],
        attestors=attestors,
        signatures=attestation_dict.get('signatures', [])
    )
    attestation_hash = encode_attestation(attestation)
    print("attestationEncode:", attestation_hash)
    print("attestationSignature:", attestation.signatures[0][2:])
    signer = recover_address(attestation_hash, attestation.signatures[0][2:])
    print("signer is:", signer)
    verify_result = signer.lower()=="0xDB736B13E2f522dBE18B2015d0291E4b193D8eF6".lower()
    print("verify result:" , verify_result)

    if verify_result is not True:
        print("Attestation verification failed.")
        return

    url = attestation.request.url
    if not (
            url.startswith("https://www.binance.com/bapi/composite/v1/private/bigdata/finance/spot-statistics") or
            url.startswith("https://www.binance.com/bapi/capital/v1/private/streamer/trade/get-user-trades") or
            url.startswith("https://www.okx.com/priapi/v5/account/bills-archive")
    ):
        print("not support url")
        return

    data = json.loads(attestation.data)
    parsed = json.loads(data["CompleteHttpResponseCiphertext"])

    packets = []
    for pkt in parsed["packets"]:
        records = [
            TLSRecord(
                ciphertext=rec["ciphertext"],
                nonce=rec["nonce"],
                json_block_positions=rec["json_block_positions"]
            ) for rec in pkt["records"]
        ]
        packets.append(HTTPPacket(records))

    tls_data = TLSData(packets)
    full_plain_response = tls_data.get_full_plain_response(aes_key)
    data = extract_data_from_http_response(full_plain_response[0])
    print("Extracted Data:\n"+json.dumps(data, indent=2))


if __name__ == "__main__":
    main()