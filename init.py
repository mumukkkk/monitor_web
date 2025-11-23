from flask import Flask, render_template, request, jsonify
import base64
import sqlite3
import os
import threading
import time
import subprocess
import json
from datetime import datetime

# 导入密码解密模块
from privacy import decrypt_password

app = Flask(__name__)

# 新的公钥参数 (e, n)
public_exponent = 65537
modulus = 11428270940227957444121972623858067884844156065700355794405296166301988372477

# 数据库文件路径
DATABASE = 'server_monitor.db'

def init_db():
    """初始化数据库，创建表"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # 创建主机表，ip、user和port为联合主键
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT NOT NULL,
            user TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            port INTEGER DEFAULT 22,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ip, user, port)
        )
    ''')
    
    # 创建监控数据表 - 添加网络流量字段
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS monitoring_data (
            ip TEXT NOT NULL,
            cpu_usage REAL,
            memory_usage REAL,
            disk_usage REAL,
            network_rx REAL DEFAULT 0,
            network_tx REAL DEFAULT 0,
            is_online INTEGER DEFAULT 0,
            check_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ip, check_time)
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    # 获取所有主机信息
    hosts = get_all_hosts()
    return render_template('index.html', hosts=hosts)

@app.route('/add_host', methods=['POST'])
def add_host():
    ip = request.form['ip']
    user = request.form['user']
    password = request.form['pwd']  # 明文密码
    port = request.form.get('port', 22)  # 默认端口22
    
    # 在服务器端进行 RSA 加密
    encrypted_password = rsa_encrypt(password)
    
    # 将主机信息保存到数据库
    success = save_host_to_db(ip, user, encrypted_password, port)
    
    if success:
        return jsonify({'success': True, 'message': '主机添加成功'})
    else:
        return jsonify({'success': False, 'message': '保存失败，可能已存在相同IP、用户名和端口的主机'})

@app.route('/update_host', methods=['POST'])
def update_host():
    old_ip = request.form['old_ip']
    old_user = request.form['old_user']
    old_port = request.form['old_port']
    
    new_ip = request.form['new_ip']
    new_user = request.form['new_user']
    new_port = request.form['new_port']
    new_password = request.form['new_pwd']
    
    # 在服务器端进行 RSA 加密
    encrypted_password = rsa_encrypt(new_password) if new_password else None
    
    # 更新主机信息
    success = update_host_in_db(old_ip, old_user, old_port, new_ip, new_user, new_port, encrypted_password)
    
    if success:
        return jsonify({'success': True, 'message': '主机更新成功'})
    else:
        return jsonify({'success': False, 'message': '更新失败'})

@app.route('/delete_host', methods=['POST'])
def delete_host():
    ip = request.form['ip']
    user = request.form['user']
    port = request.form['port']
    confirm_user = request.form['confirm_user']
    
    # 验证用户名
    if confirm_user != user:
        return jsonify({'success': False, 'message': '用户名不匹配，删除失败'})
    
    # 从数据库删除主机
    success = delete_host_from_db(ip, user, port)
    
    if success:
        return jsonify({'success': True, 'message': '主机删除成功'})
    else:
        return jsonify({'success': False, 'message': '删除失败'})

@app.route('/monitoring_data')
def show_monitoring_data():
    """显示监控数据"""
    data = get_monitoring_data()
    html = "<h1>监控数据</h1><table border='1'><tr><th>IP</th><th>CPU使用率</th><th>内存使用率</th><th>磁盘使用率</th><th>检查时间</th></tr>"
    for row in data:
        html += f"<tr><td>{row[0]}</td><td>{row[1]:.2f}%</td><td>{row[2]:.2f}%</td><td>{row[3]:.2f}%</td><td>{row[4]}</td></tr>"
    html += "</table><br><a href='/'>返回主页</a>"
    return html

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

def save_host_to_db(ip, user, encrypted_password, port=22):
    """将主机信息保存到数据库"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # 使用 INSERT OR REPLACE 来处理重复键（更新密码）
        cursor.execute('''
            INSERT OR REPLACE INTO hosts (ip, user, encrypted_password, port)
            VALUES (?, ?, ?, ?)
        ''', (ip, user, encrypted_password, port))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return False

def update_host_in_db(old_ip, old_user, old_port, new_ip, new_user, new_port, encrypted_password):
    """更新主机信息"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # 如果密码为空，则只更新IP、用户名和端口
        if encrypted_password:
            cursor.execute('''
                UPDATE hosts 
                SET ip = ?, user = ?, port = ?, encrypted_password = ?
                WHERE ip = ? AND user = ? AND port = ?
            ''', (new_ip, new_user, new_port, encrypted_password, old_ip, old_user, old_port))
        else:
            cursor.execute('''
                UPDATE hosts 
                SET ip = ?, user = ?, port = ?
                WHERE ip = ? AND user = ? AND port = ?
            ''', (new_ip, new_user, new_port, old_ip, old_user, old_port))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return False

def delete_host_from_db(ip, user, port):
    """从数据库删除主机"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM hosts WHERE ip = ? AND user = ? AND port = ?', (ip, user, port))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return False

def get_all_hosts():
    """获取所有主机信息"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT ip, user, encrypted_password, port, created_at FROM hosts')
        hosts = cursor.fetchall()
        
        conn.close()
        return hosts
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return []

def get_monitoring_data():
    """获取监控数据"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT ip, cpu_usage, memory_usage, disk_usage, check_time FROM monitoring_data ORDER BY check_time DESC LIMIT 100')
        data = cursor.fetchall()
        
        conn.close()
        return data
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return []

def save_monitoring_data(ip, cpu_usage, memory_usage, disk_usage, is_online=0, network_rx=0, network_tx=0):
    """保存监控数据到数据库"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO monitoring_data (ip, cpu_usage, memory_usage, disk_usage, network_rx, network_tx, is_online)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (ip, cpu_usage, memory_usage, disk_usage, network_rx, network_tx, is_online))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return False

def collect_monitoring_data():
    """采集监控数据"""
    hosts = get_all_hosts()
    
    for host in hosts:
        ip, user, encrypted_password, port, _ = host
        
        # 解密密码
        password = decrypt_password(encrypted_password)
        if not password:
            print(f"无法解密密码 for {ip}, 跳过")
            continue
        
        # 使用Ansible采集数据
        try:
            # 创建临时inventory文件
            inventory_content = f"""
[all]
{ip}

[all:vars]
ansible_connection=ssh
ansible_ssh_user={user}
ansible_ssh_pass={password}
ansible_ssh_port={port}
ansible_become_pass={password}
"""
            
            with open('ansible_inventory', 'w') as f:
                f.write(inventory_content)
            
            # 执行ping命令检查上线情况
            ping_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "ping"]
            result = subprocess.run(ping_cmd, capture_output=True, text=True)
            output = result.stdout.strip()
            
            if "SUCCESS" in output and "pong" in output:
                print(f"{ip} | 成功响应")
                is_online = 1
                
                try:
                    # 执行Ansible命令获取CPU使用率
                    cpu_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell", 
                            "-a", "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'"]
                    cpu_result = subprocess.run(cpu_cmd, capture_output=True, text=True)
                    cpu_output = cpu_result.stdout.strip().split('\n')[-1]
                    cpu_usage = float(cpu_output) if cpu_result.returncode == 0 and cpu_output.replace('.', '').isdigit() else 0.0
                except:
                    cpu_usage = 0.0
                
                try:
                    # 执行Ansible命令获取内存使用率
                    memory_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell",  
                            "-a", "free | grep Mem | awk '{print $3/$2 * 100.0}'"]
                    memory_result = subprocess.run(memory_cmd, capture_output=True, text=True)
                    memory_output = memory_result.stdout.strip().split('\n')[-1]
                    memory_usage = float(memory_output) if memory_result.returncode == 0 and memory_output.replace('.', '').isdigit() else 0.0
                except:
                    memory_usage = 0.0
                
                try:
                    # 执行Ansible命令获取磁盘使用率
                    disk_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell", 
                            "-a", "df / | awk 'NR==2 {print $5}' | sed 's/%//'"]
                    disk_result = subprocess.run(disk_cmd, capture_output=True, text=True)
                    disk_output = disk_result.stdout.strip().split('\n')[-1]
                    disk_usage = float(disk_output) if disk_result.returncode == 0 and disk_output.replace('.', '').isdigit() else 0.0
                except:
                    disk_usage = 0.0
                
                # ========== 修改后的网络流量数据采集 ==========
                try:
                    # 执行Ansible命令获取网络流量数据
                    network_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell", 
                                "-a", "cat /proc/net/dev | grep -E '(eth0|ens|enp)' | head -1 | awk '{print $2\" \"$10}'"]
                    network_result = subprocess.run(network_cmd, capture_output=True, text=True)
                    network_output = network_result.stdout.strip()
                    
                    if network_result.returncode == 0 and network_output:
                        # 处理Ansible输出，提取数字部分
                        # Ansible输出格式通常是: "192.168.1.100 | SUCCESS | rc=0 >>\n12345 67890"
                        lines = network_output.split('\n')
                        # 取最后一行，应该是数字
                        last_line = lines[-1].strip()
                        
                        # 检查是否是数字行
                        if last_line.replace(' ', '').isdigit():
                            rx_bytes, tx_bytes = map(int, last_line.split())
                            
                            # 计算网络流量（转换为MB）
                            network_rx = rx_bytes / 1024 / 1024  # 转换为MB
                            network_tx = tx_bytes / 1024 / 1024  # 转换为MB
                            
                            print(f"采集到 {ip} 的网络流量: RX={network_rx:.2f}MB, TX={network_tx:.2f}MB")
                        else:
                            # 如果输出格式不对，标记为采集失败
                            print(f"采集 {ip} 网络流量数据失败：输出格式不正确")
                            network_rx = 0.0
                            network_tx = 0.0
                    else:
                        # 如果获取失败，标记为采集失败
                        print(f"采集 {ip} 网络流量数据失败：命令执行失败")
                        network_rx = 0.0
                        network_tx = 0.0
                except Exception as e:
                    print(f"采集 {ip} 网络流量数据时出错: {e}")
                    # 网络流量数据采集失败，使用0值
                    network_rx = 0.0
                    network_tx = 0.0
                # ========== 网络流量数据采集结束 ==========`
                
                print(f"采集到 {ip} 的数据: CPU={cpu_usage:.2f}%, 内存={memory_usage:.2f}%, 磁盘={disk_usage:.2f}%")
                
                # 保存到数据库 - 添加网络流量参数
                save_monitoring_data(ip, cpu_usage, memory_usage, disk_usage, is_online, network_rx, network_tx)
                
            else:
                print(f"{ip} | 未成功响应: {output}")
                # 保存离线状态，其他指标设为0
                is_online = 0
                save_monitoring_data(ip, 0.0, 0.0, 0.0, is_online, 0.0, 0.0)
                
        except Exception as e:
            print(f"采集 {ip} 数据时出错: {e}")
            # 保存错误状态
            save_monitoring_data(ip, 0.0, 0.0, 0.0, 0, 0.0, 0.0)
    
    # 删除临时文件
    try:
        os.remove('ansible_inventory')
    except:
        pass

def monitoring_loop():
    """监控循环"""
    while True:
        print(f"{datetime.now()}: 开始采集监控数据")
        collect_monitoring_data()
        print(f"{datetime.now()}: 监控数据采集完成，等待30秒")
        time.sleep(30)  # 取消注释，恢复30秒等待

# 添加一个路由来查看所有主机（用于调试）
@app.route('/hosts')
def show_hosts():
    hosts = get_all_hosts()
    html = "<h1>已添加的主机</h1><table border='1'><tr><th>IP</th><th>用户名</th><th>端口</th><th>加密密码</th><th>添加时间</th></tr>"
    for host in hosts:
        html += f"<tr><td>{host[0]}</td><td>{host[1]}</td><td>{host[3]}</td><td>{host[2][:20]}...</td><td>{host[4]}</td></tr>"
    html += "</table><br><a href='/'>返回主页</a>"
    return html

@app.route('/get_real_time_data')
def get_real_time_data():
    """获取所有主机的实时监控数据"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # 获取每个主机的最新监控数据
        cursor.execute('''
            SELECT md.ip, md.cpu_usage, md.memory_usage, md.disk_usage, md.network_rx, md.network_tx, md.is_online, md.check_time
            FROM monitoring_data md
            INNER JOIN (
                SELECT ip, MAX(check_time) as latest_time
                FROM monitoring_data
                GROUP BY ip
            ) latest ON md.ip = latest.ip AND md.check_time = latest.latest_time
        ''')
        
        data = cursor.fetchall()
        conn.close()
        
        # 转换为字典格式便于前端使用
        result = {}
        for row in data:
            result[row[0]] = {
                'cpu_usage': row[1],
                'memory_usage': row[2],
                'disk_usage': row[3],
                'network_rx': row[4],
                'network_tx': row[5],
                'is_online': row[6],
                'check_time': row[7]
            }
        
        return jsonify(result)
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return jsonify({})  # 修复这行，移除多余的 ({})

@app.route('/monitor_dashboard')
def monitor_dashboard():
    """监控大屏页面"""
    return render_template('monitor_dashboard.html')

if __name__ == '__main__':
    # 初始化数据库
    init_db()
    
    # 启动监控线程
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    
    app.run(host='0.0.0.0', port=80)

