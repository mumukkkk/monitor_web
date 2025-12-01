import base64

# RSA 私钥参数
private_exponent = 1058654391841615112734249291231553628139757104952992188933670721023764697121
modulus = 11428270940227957444121972623858067884844156065700355794405296166301988372477

def decrypt_password(encrypted_password):
    """解密密码"""
    try:
        # 将Base64解码为字节
        encrypted_bytes = base64.b64decode(encrypted_password)
        
        # 将字节转换为整数
        ciphertext = int.from_bytes(encrypted_bytes, 'big')
        
        # RSA解密: plaintext = ciphertext^private_exponent mod modulus
        plaintext_int = pow(ciphertext, private_exponent, modulus)
        
        # 将整数转换回字符串
        decrypted_pwd = int_to_text(plaintext_int)
        
        return decrypted_pwd
    except Exception as e:
        print(f"解密错误: {e}")
        return None

def int_to_text(n):
    """将整数转换回文本"""
    text = ""
    while n > 0:
        text = chr(n & 0xFF) + text
        n = n >> 8
    return text
