from flask import Flask, render_template, request
import base64

app = Flask(__name__)
# 公钥参数 (e, n)
public_exponent = 65537
modulus = 63581406165266793531989575153458561744457706129485308583125449488895890573163
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/add_host', methods=['POST'])
def add_host():
    ip = request.form['ip']
    user = request.form['user']
    password = request.form['pwd']  # 明文密码
    # 进行 RSA 加密
    encrypted_password = rsa_encrypt(password)
    print(f"收到主机信息: IP={ip}, 用户={user}, 明文密码={password}, 加密密码={encrypted_password}")
    
    # 这里可以添加实际的主机添加逻辑，例如存储加密后的密码
    
    # 返回成功页面，5秒后自动跳转
    return render_template('success.html')

def rsa_encrypt(message):
    """使用 RSA 公钥加密消息"""
    try:
        # 将消息转换为整数
        m = text_to_int(message)  
        # 检查消息是否小于模数
        if m >= modulus:
            raise ValueError("消息太长，无法使用当前密钥加密")
        # 计算 c = m^e mod n
        c = pow(m, public_exponent, modulus)
        # 将加密结果转换为 Base64 以便存储/传输
        return base64.b64encode(c.to_bytes((c.bit_length() + 7) // 8, 'big')).decode()
    except Exception as e:
        print(f"加密错误: {e}")
        return f"加密失败: {str(e)}"
def text_to_int(text):
    """将文本转换为整数"""
    n = 0
    for char in text:
        n = n * 256 + ord(char)
    return n

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
