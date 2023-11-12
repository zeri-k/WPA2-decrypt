import hashlib
import binascii
import hmac
import binascii
from Crypto.Cipher import AES # pip install pycrypto pycryptodome pycryptodomex
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

passphrase = "1234567890"
SSID = "test_wifi_5G"
ssid_bytes = SSID.encode()

psk = hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid_bytes, 4096, 32)
psk_hex = binascii.hexlify(psk).decode()
print("PSK :", psk_hex)

pmk = psk

def prf_80211i(K, A, B, Len):
    R = b""
    i = 0
    while i <= ((Len + 159) / 160):
        hmac_result = hmac.new(K, A + bytes.fromhex("00") + B + bytes([i]), hashlib.sha1).digest()
        i += 1
        R += hmac_result
    return binascii.hexlify(R).decode()[:128]

def generate_ptk(pmk, anonce, snonce, AP_Addr, STA_Addr):
    ptk = prf_80211i(pmk, b"Pairwise key expansion", min(AP_Addr, STA_Addr) + max(AP_Addr, STA_Addr) + min(anonce, snonce) + max(anonce, snonce), 384)

    kck = ptk[:32]
    kek = ptk[32:64]
    tk = ptk[64:96]
    mic_tx = ptk[96:112]
    mic_rx = ptk[112:]

    return ptk, kck, kek, tk, mic_tx, mic_rx

anonce = bytes.fromhex("405710017abbe7f080f21b9ecadfbf6f8ea44f107e9ab93d22cfd7165753d1a9")
snonce = bytes.fromhex("1c6b8c0275ead8b4a9ff2683d1e1c8a7ba8b58510a60eb1976d148d2bb53b183")
ap_mac = bytes.fromhex("00:df:fa:fd:ff:ff".replace(":",""))
client_mac = bytes.fromhex("b2:81:0a:c4:2b:c5".replace(":",""))

ptk, kck, kek, tk, mic_tx, mic_rx = generate_ptk(pmk, anonce, snonce, ap_mac, client_mac)
print("Generated PTK :", kck, kek, tk, mic_tx, mic_rx)


def generate_gtk(kek, key_wrap_data):
    decrypt_key_wrap_data = aes_key_unwrap(bytes.fromhex(kek), bytes.fromhex(key_wrap_data))
    decrypt_key_wrap_data = binascii.hexlify(decrypt_key_wrap_data).decode()
    return decrypt_key_wrap_data[60:-4]

key_wrap_data = "90caef00f80b7af3a993028bd75c9d41523f3e7406b7ad522543cfe49808eb8d0d73df9e1214ae4a880c68ecc95c1c238f28f15efb7cf451"
gtk = generate_gtk(kek, key_wrap_data)
print("GTK :", gtk)


# ccmp 메시지 복호화
qos_data_frame = bytes.fromhex("ad1395aad2aa6888a91d3288e740678e12f020ec6c605389431d278390039f3da8f33ce5f87a9510bbc7de39fe6f02bcbbb1266caf728959061bce73ecee04f5864b57f25aa3900eb34b1c2c3ea7ea8b61c79ff390bdf9d2567566d17f1a50537d20d0ae65b724f3c3730f80d3dd924de40f00114e54ca01b338e35894441efee6be7be7b9d7737fd721f23f38901681f762eb9cdde9fc6aaf43c48be2daef15c8321c3798cd216c66e55927be7aa5b792a51a8b7debcf5e4b885ef8355ffedab3344f00c51944b0553e26b6cf6b264abca0515436b82893943168051e26cfb4455c29fd2f9136ef8b51fe2db3fe0e0a5da55d3403f5d24c33268f12672847bb1ed5307b151c32eb7b84f18795162bb44bea47db85cb063637f36d97f92e18f5cc4159db360a3db4ae08ad46621fb505bbb2fa0f82df1d1b23974b238d110faed511d2ab3ba308ad398a8d07deaeb61d5e62192c76ba38d6eb9a74bc836084066b9bed0d3fc98371b05f3921d3b65010d6f030ad4a627e95a7c3a5b53f7d2e6b646a83564fc79a9374fca274653d03ed9c8020da9352decf474d467efa964ecd1359ac4cd5bdb834f8a364f28c5d2780c774971f54bc8d0c7e967decb29fc7c853c681d9ad57df98970620b1b6b6a14445d3d35e9100f7499b1256cba9d77ffcd3a5d0eb6411f07fc2853bba7e86674638543e475b785f4857ba9c6b50ddd4a8724b72aa8de03f514c3c75476378561adc5ac7e14c3a7d57d008e3c2ccfa6d882567acbd391a390712d37d03")

def decrypt_data(tk, qos_data_frame):
    ccmp_key = bytes.fromhex(tk)
    priority = bytes.fromhex("00")
    ccmp_iv = bytes.fromhex("0000000001AE")
    nonce = priority + client_mac + ccmp_iv

    cipher = AES.new(ccmp_key, AES.MODE_CCM, nonce, mac_len=8)
    return cipher.decrypt(qos_data_frame)

plaintext = decrypt_data(tk, qos_data_frame)
print(plaintext.decode(errors='replace'))
