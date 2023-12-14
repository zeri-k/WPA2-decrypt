import hashlib
import binascii
import hmac
import binascii
from typing import Tuple
from Crypto.Cipher import AES # pip install cryptography pycryptodome
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from scapy.all import RadioTap, Dot11QoS, Dot11CCMP, LLC, hexstr, EAPOL, Raw


def prf_80211i(K: bytes, A: bytes, B: bytes, Len: int):
    R = b""
    i = 0
    while i <= ((Len + 159) / 160):
        hmac_result = hmac.new(K, A + bytes.fromhex("00") + B + bytes([i]), hashlib.sha1).digest()
        i += 1
        R += hmac_result
    return binascii.hexlify(R).decode()[:128]

def generate_pmk(ssid: str, passphrase: str):
    psk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)
    psk_hex = binascii.hexlify(psk).decode()
    print("PSK :", psk_hex)
    return psk

def generate_ptk(pmk: bytes, anonce: bytes, snonce: bytes, AP_Addr: bytes, STA_Addr: bytes):
    ptk = prf_80211i(pmk, b"Pairwise key expansion", min(AP_Addr, STA_Addr) + max(AP_Addr, STA_Addr) + min(anonce, snonce) + max(anonce, snonce), 384)
    kck = bytes.fromhex(ptk[:32])
    kek = bytes.fromhex(ptk[32:32+32])
    tk = bytes.fromhex(ptk[64:64+32])
    mic_tx = bytes.fromhex(ptk[96:96+16])
    mic_rx = bytes.fromhex(ptk[112:])
    return ptk, kck, kek, tk, mic_tx, mic_rx

def extract_gtk(kek: bytes, key_wrap_data: bytes):
    decrypt_key_wrap_data = aes_key_unwrap(kek, key_wrap_data)
    decrypt_key_wrap_data = binascii.hexlify(decrypt_key_wrap_data).decode()
    return bytes.fromhex(decrypt_key_wrap_data[60:-4])

def eapol_decoding(packet):
    eapol_message = packet[EAPOL].load
    dot1xAuth = {}
    message_number = {"008a":1, "010a":2, "13ca":3, "030a":4}
    dot1xAuth["key_descriptor_type"] = bytes.hex(eapol_message)[:2]
    dot1xAuth["key_information"] = bytes.hex(eapol_message)[2:2+4]
    dot1xAuth["key_length"] = bytes.hex(eapol_message)[6:6+4]
    dot1xAuth["replay_conter"] = bytes.hex(eapol_message)[10:10+16]
    dot1xAuth["wpa_key_nonce"] = bytes.hex(eapol_message)[26:26+64]
    dot1xAuth["key_iv"] = bytes.hex(eapol_message)[90:90+32]
    dot1xAuth["wpa_key_rsc"] = bytes.hex(eapol_message)[122:122+16]
    dot1xAuth["wpa_key_id"] = bytes.hex(eapol_message)[138:138+16]
    dot1xAuth["wpa_key_mic"] = bytes.hex(eapol_message)[154:154+32]
    dot1xAuth["wpa_key_data_length"] = bytes.hex(eapol_message)[186:186+4]
    dot1xAuth["wpa_key_data"] = bytes.hex(eapol_message)[190:]
    dot1xAuth["message_number"] = message_number.get(dot1xAuth.get("key_information"))
    return dot1xAuth

def get_priority(packet):
    qos_data = packet[Dot11QoS]
    qos_control = hexstr(qos_data).replace(' ', '')[:4]
    qos_control = qos_control[2:] + qos_control[:2]
    tid = int(qos_control[3], 16)
    priority = bin(tid)[2:].zfill(4)[1:]
    priority = int(priority, 2)
    priority = bytes.fromhex(hex(priority)[2:].zfill(2))
    return priority

def parse_ccmp_packet(packet) -> Tuple[bytes, bytes]:
    ccmp_data = packet[Dot11CCMP]
    ccmp_header = hexstr(ccmp_data).replace(' ', '')[:16]
    ccmp_header = [ccmp_header[i:i+2] for i in range(0, len(ccmp_header), 2)]
    ccmp_header.pop(2) # reserved "00" pop
    ext_iv_key_id = bytes.fromhex(ccmp_header.pop(2))
    ext_iv_key_id = bin(ext_iv_key_id[0])[2:].zfill(8)
    key_id = int(ext_iv_key_id[:2], 2)
    ext_iv = ext_iv_key_id[2]
    ccmp_header.reverse()
    ccmp_iv = bytes.fromhex(''.join(ccmp_header))
    encrypted_data = ccmp_data.data
    return ccmp_iv, encrypted_data

def wpa2_decrypt(tk: bytes, priority: bytes, station_mac: bytes, ccmp_iv: bytes, encrypted_data: bytes):
    ccmp_key = tk
    nonce = priority + station_mac + ccmp_iv
    cipher = AES.new(ccmp_key, AES.MODE_CCM, nonce, mac_len=8)
    plain_data = cipher.decrypt(encrypted_data)
    return plain_data

def wpa2_encrypt(tk: bytes, priority: bytes, station_mac: bytes, ccmp_iv: bytes, plain_data: bytes):
    ccmp_key = tk
    nonce = priority + station_mac + ccmp_iv
    cipher = AES.new(ccmp_key, AES.MODE_CCM, nonce, mac_len=8)
    encrypted_data = cipher.encrypt(plain_data)
    return encrypted_data


def main():
    ssid = "test_wifi_5G"
    passphrase = "1234567890"
    anonce = b""
    snonce = b""
    ap_mac = b""
    station_mac = b""
    key_wrap_data = b""
    pmk = generate_pmk(ssid, passphrase)

    packet_list = ["00003a006b081c40354cf9a400000000100071164001cea10100888e40010100711695221f08000000000000080000e90010180304003c0e000088024c00d4548b3c1a4a00dffafdffff00dffafdffff00000000aaaa03000000888e0103007502008a001000000000000000019e4fe9e1b2fb972c0a3c0e1f405355ba05c51284b2ba90b7c6ef3e1e986adf420000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016dd14000fac0400000000000000000000000000000000a17b6f99",
    "00003a006b081c40d550f9a400000000100071164001d5a10100888e40010100711695221f08000000000000080000b5001018030400ddde000088013c0000dffafdffffd4548b3c1a4a00dffafdffff00000000aaaa03000000888e0103007702010a00000000000000000001672db563afa752a96adddeaf64b5058561f9b90abfacacf69313062987d1f8b800000000000000000000000000000000000000000000000000000000000000000cd2bfc70295bae98da443226ede8b76001830160100000fac040100000fac040100000fac023c000000cd045b6d",
    "00003a006b081c400555f9a400000000100071164001cfa10100888e40010100711695221f08000000000000080000e90010180304003c0e000088024c00d4548b3c1a4a00dffafdffff00dffafdffff10000000aaaa03000000888e010300970213ca001000000000000000029e4fe9e1b2fb972c0a3c0e1f405355ba05c51284b2ba90b7c6ef3e1e986adf429e4fe9e1b2fb972c0a3c0e1f405355baa804000000000000000000000000000054c2b9c82ba417c65e99691783ae78f5003853d62030537dc55716ea2b1e27f8dd7d325bfc062874e2c648576a7c98a25cb53f0de5c958e508274a27320a11ff468d1a757adaf08561d4df0d4982"]

    for packet in packet_list:
        radioTap = RadioTap(bytes.fromhex(packet))
        if radioTap.haslayer(EAPOL) and radioTap[EAPOL].type == 3:  # EAPOL_KEY
            eapol_message = eapol_decoding(radioTap)
            if eapol_message.get("message_number") == 1:
                anonce = bytes.fromhex(eapol_message.get("wpa_key_nonce"))
                ap_mac = bytes.fromhex(radioTap.addr2.replace(":",""))
                station_mac = bytes.fromhex(radioTap.addr1.replace(":",""))
            elif eapol_message.get("message_number") == 2:
                snonce = bytes.fromhex(eapol_message.get("wpa_key_nonce"))
            elif eapol_message.get("message_number") == 3:
                key_wrap_data = bytes.fromhex(eapol_message.get("wpa_key_data"))

    ptk, kck, kek, tk, mic_tx, mic_rx = generate_ptk(pmk, anonce, snonce, ap_mac, station_mac)
    print("Generated PTK :", bytes.hex(kck), bytes.hex(kek), bytes.hex(tk), bytes.hex(mic_tx), bytes.hex(mic_rx))

    gtk = extract_gtk(kek, key_wrap_data)
    print("GTK :", bytes.hex(gtk))

    packet = bytes.fromhex("00003a006b0830406bb0a1a500000000141271164001d6a10100000086030000080000caff011600820000000100ff01001018030400193900008841300000dffafdffffd4548b3c1a4a00dffafdfffff01210412e01002000000000bde4ac3b3e6065cae88286019291685b000f76c90744de7bd4ad1939364af4a709319734a30cdd74094ff462a8fa96aa07d824326741958183e49db3531d58065b94ffd3ef18b500cf51e367cd59dd5c7a298733eee8e8762554af7ec4e436d62579e4d4050a758103d25f6d3c37744147e18462c18ff4f44d8481cc8f6a8e3cb52e63c9db03f071a8595294e101d27809f6bbff8c5f96067388f800ab3e9ea9127282a8023d70b6f801b285b6b7ac4584efe3ac4ada4173182e93a1d7dee8c28523186a2968af5c66906abc653a230e189704af2819c72e67e7ce0ea602b1030ae261f7bcfff5ac231342e5311476ff49e6f0375c59b113b23d5d7d7110068f9ab236d7a693ba1158b75dfd86c898fa0dc66f7aa34c0047233e183260acd634d72fa22baddd3082f1caa3575e30e218800633c48e938b63bab1d8987d1c4c8e41119c6d5895398f67dba11473c0474597bc303076544a8b7f3d4953b6375a979c744ca2a020e50b83beb9cdfe77b8c479637de16994c4577384f17c61a3331a24b3647ccddad3a2b4ec660025258d2a470de24b75492d3ca1b9e5f4d1eb3d85676aa08201147eca527471a06c11dd16aefc0d40a910edc3a52c7d1225d69fad6818f6be7504328fcba41dc564a55013031f486cba4c7b03c863708e61e8e59aacd0fbee7bd06b1feb1892dcc305e616c46eea7ce63f389ef1c12b82ee4973affd481ced62cf888b574c01039795e29db0880bb8cc6036ff0e826181d29c805201d81f2ab052c031e487351d5cd7b85e8eb1627bfda5ac5644f1e619a63ee1f941146f318f672b4789b176346e15fb5d732d9e11976369ec21efd95aa362978faa3fd1a4fe6d3274cec2d055d07b")
    radioTap = RadioTap(packet)

    if Dot11QoS in radioTap:
        priority = get_priority(radioTap)
    else:
        priority = bytes.fromhex("00")

    if Dot11CCMP in radioTap:
        ccmp_iv, encrypted_data = parse_ccmp_packet(radioTap)

    plain_data = wpa2_decrypt(tk, priority, station_mac, ccmp_iv, encrypted_data)
    LLC_frame = LLC(plain_data)
    # LLC_frame.show()
    application_layer = LLC_frame[Raw].load
    print(application_layer.decode())


if __name__ == '__main__':
    main()
