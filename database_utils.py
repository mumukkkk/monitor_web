import sqlite3
import os
import pytz 
from datetime import datetime

class DatabaseUtils:
    def __init__(self, db_path='server_monitor.db'):
        self.db_path = db_path
        self.shanghai_tz = pytz.timezone('Asia/Shanghai')
        self.init_db()
    
    def init_db(self):
        """初始化数据库，创建表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA timezone = 'Asia/Shanghai'")
        
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
                check_time TIMESTAMP ,
                PRIMARY KEY (ip, check_time)
            )
        ''')
        conn.commit()
        conn.close()

    def get_connection(self):
        """获取数据库连接，确保时区设置"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA timezone = 'Asia/Shanghai'")
        return conn
    
    def get_all_hosts(self):
        """获取所有主机信息"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT ip, user, encrypted_password, port, created_at FROM hosts')
            hosts = cursor.fetchall()
            
            conn.close()
            return hosts
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return []
    
    def save_monitoring_data(self, ip, cpu_usage, memory_usage, disk_usage, is_online=0, network_rx=0, network_tx=0):
    """保存监控数据到数据库"""
    try:
        conn = self.get_connection()
        cursor = conn.cursor()
        
       
        check_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO monitoring_data (ip, cpu_usage, memory_usage, disk_usage, network_rx, network_tx, is_online, check_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ip, cpu_usage, memory_usage, disk_usage, network_rx, network_tx, is_online, check_time))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        self.logger.error(f"保存监控数据失败: {e}")
        return False

    
    def cleanup_old_data(self, days=30):
        """清理指定天数前的监控数据"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM monitoring_data 
                WHERE check_time < date('now', '-{} days')
            '''.format(days))
            
            deleted_rows = cursor.rowcount
            conn.commit()
            conn.close()
            
            print(f"已清理 {deleted_rows} 条 {days} 天前的监控数据")
            return True
        except sqlite3.Error as e:
            print(f"清理数据时出错: {e}")
            return False

