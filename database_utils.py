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
        
        # 创建自定义监控指标配置表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                metric_description TEXT,
                command TEXT NOT NULL,
                unit TEXT DEFAULT '%',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 创建自定义监控指标数据表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_metric_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                value REAL NOT NULL,
                check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (metric_id) REFERENCES custom_metrics (id)
            )
        ''')
        
        # 创建索引
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_custom_metric_data_time 
            ON custom_metric_data (check_time)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_custom_metric_data_ip_time 
            ON custom_metric_data (ip, check_time)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_custom_metric_data_metric 
            ON custom_metric_data (metric_id, check_time)
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
            
            check_time = datetime.now(self.shanghai_tz).strftime('%Y-%m-%d %H:%M:%S')
            
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
    
    def get_monitoring_data_by_host(self, host_ip):
        """
        获取指定主机的最新监控数据
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM monitoring_data WHERE ip = ? ORDER BY check_time DESC LIMIT 1", (host_ip,))
            data = cursor.fetchone()
            conn.close()
            return data
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return None
        
    def get_historical_data_by_metric(self, host_ip, metric_field, start_time, end_time, limit=1000):
        """
        获取指定主机和指标的历史数据
        
        Args:
            host_ip: 主机IP地址
            metric_field: 指标字段名
            start_time: 开始时间
            end_time: 结束时间
            limit: 返回记录的最大数量
            
        Returns:
            历史数据列表，每个元素为(check_time, metric_value)元组
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 构建SQL查询
            query = f"SELECT check_time, {metric_field} FROM monitoring_data " \
                    f"WHERE ip = ? AND check_time BETWEEN ? AND ? " \
                    f"ORDER BY check_time ASC LIMIT ?"
            
            cursor.execute(query, (host_ip, start_time, end_time, limit))
            data = cursor.fetchall()
            
            conn.close()
            return data
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return []
        
    def get_multiple_metrics_history(self, host_ip, metric_fields, start_time, end_time, limit=1000):
        """
        获取指定主机多个指标的历史数据
        
        Args:
            host_ip: 主机IP地址
            metric_fields: 指标字段名列表
            start_time: 开始时间
            end_time: 结束时间
            limit: 返回记录的最大数量
            
        Returns:
            字典，键为指标名，值为历史数据列表
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 构建SQL查询
            fields_str = ", ".join(['check_time'] + metric_fields)
            query = f"SELECT {fields_str} FROM monitoring_data " \
                    f"WHERE ip = ? AND check_time BETWEEN ? AND ? " \
                    f"ORDER BY check_time ASC LIMIT ?"
            
            cursor.execute(query, (host_ip, start_time, end_time, limit))
            rows = cursor.fetchall()
            
            # 整理数据
            result = {}
            for field in metric_fields:
                result[field] = []
            
            field_indices = {}
            # 获取每个字段在结果中的索引
            for i, desc in enumerate(cursor.description):
                if desc[0] != 'check_time':
                    field_indices[desc[0]] = i
            
            # 填充数据
            for row in rows:
                check_time = row[0]
                for field in metric_fields:
                    if field in field_indices:
                        value = row[field_indices[field]]
                        result[field].append((check_time, value))
            
            conn.close()
            return result
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return {}
    
    def calculate_metric_statistics(self, host_ip, metric_field, start_time, end_time):
        """
        计算单个指标的统计数据
        
        Args:
            host_ip: 主机IP地址
            metric_field: 指标字段名
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            包含统计数据的字典：平均值、峰值、最小值、中位数、标准差
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取原始数据
            query = f"SELECT {metric_field} FROM monitoring_data " \
                    f"WHERE ip = ? AND check_time BETWEEN ? AND ? " \
                    f"ORDER BY {metric_field} ASC"
            
            cursor.execute(query, (host_ip, start_time, end_time))
            data = cursor.fetchall()
            
            if not data:
                conn.close()
                return {
                    'average': 0,
                    'peak': 0,
                    'minimum': 0,
                    'median': 0,
                    'std_dev': 0,
                    'count': 0
                }
            
            # 提取数值并过滤None值
            values = [row[0] for row in data if row[0] is not None]
            count = len(values)
            
            if count == 0:
                conn.close()
                return {
                    'average': 0,
                    'peak': 0,
                    'minimum': 0,
                    'median': 0,
                    'std_dev': 0,
                    'count': 0
                }
            
            # 计算基本统计数据
            import statistics
            
            average = sum(values) / count
            
            # 计算最小值、最大值和中位数时剔除使用率一直为0%的数据点
            non_zero_values = [v for v in values if v > 0]
            
            # 计算最大值（峰值）
            peak = max(non_zero_values) if non_zero_values else max(values)
            
            # 计算最小值
            minimum = min(non_zero_values) if non_zero_values else min(values)
            
            # 计算中位数
            median = statistics.median(non_zero_values) if non_zero_values else statistics.median(values)
            
            std_dev = statistics.stdev(values) if count > 1 else 0
            
            conn.close()
            
            return {
                'average': round(average, 2),
                'peak': round(peak, 2),
                'minimum': round(minimum, 2),
                'median': round(median, 2),
                'std_dev': round(std_dev, 2),
                'count': count
            }
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return {
                'average': 0,
                'peak': 0,
                'minimum': 0,
                'median': 0,
                'std_dev': 0,
                'count': 0
            }
        except Exception as e:
            print(f"计算统计数据时出错: {e}")
            return {
                'average': 0,
                'peak': 0,
                'minimum': 0,
                'median': 0,
                'std_dev': 0,
                'count': 0
            }
    
    def get_metric_statistics(self, host_ip, metric_fields, start_time, end_time):
        """
        获取多个指标的统计数据
        
        Args:
            host_ip: 主机IP地址
            metric_fields: 指标字段名列表
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            字典，键为指标名，值为统计数据字典
        """
        result = {}
        for field in metric_fields:
            result[field] = self.calculate_metric_statistics(host_ip, field, start_time, end_time)
        return result
    
    def get_all_hosts_statistics(self, metric_field, start_time, end_time):
        """
        获取所有主机的统计数据
        
        Args:
            metric_field: 指标字段名
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            字典，键为主机IP，值为统计数据字典
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取所有主机IP
            cursor.execute("SELECT DISTINCT ip FROM monitoring_data")
            hosts = cursor.fetchall()
            
            result = {}
            for host in hosts:
                host_ip = host[0]
                result[host_ip] = self.calculate_metric_statistics(host_ip, metric_field, start_time, end_time)
            
            conn.close()
            return result
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return {}
    
    def get_metrics_for_chart(self, host_ip, metric_fields, start_time, end_time, limit=1000):
        """
        获取用于图表展示的历史数据
        
        Args:
            host_ip: 主机IP地址
            metric_fields: 指标字段名列表
            start_time: 开始时间
            end_time: 结束时间
            limit: 返回记录的最大数量
            
        Returns:
            包含时间标签和各指标数据的字典
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 构建SQL查询
            fields_str = ", ".join(['check_time'] + metric_fields)
            query = f"SELECT {fields_str} FROM monitoring_data " \
                    f"WHERE ip = ? AND check_time BETWEEN ? AND ? " \
                    f"ORDER BY check_time ASC LIMIT ?"
            
            cursor.execute(query, (host_ip, start_time, end_time, limit))
            rows = cursor.fetchall()
            
            # 整理数据
            chart_data = {
                'labels': [],
                'datasets': {}
            }
            
            for field in metric_fields:
                chart_data['datasets'][field] = []
            
            # 填充数据
            for row in rows:
                check_time = row[0]
                chart_data['labels'].append(check_time)
                
                for i, field in enumerate(metric_fields):
                    value = row[i+1]  # 第一个元素是check_time
                    chart_data['datasets'][field].append(value)
            
            conn.close()
            return chart_data
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return {
                'labels': [],
                'datasets': {}
            }
    
    # 自定义监控指标相关方法
    def add_custom_metric(self, metric_name, metric_description, command, unit='%'):
        """
        添加自定义监控指标
        
        Args:
            metric_name: 指标名称
            metric_description: 指标描述
            command: 执行命令
            unit: 指标单位
            
        Returns:
            成功返回True，失败返回False
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO custom_metrics (metric_name, metric_description, command, unit)
                VALUES (?, ?, ?, ?)
            ''', (metric_name, metric_description, command, unit))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return False
    
    def update_custom_metric(self, metric_id, metric_name, metric_description, command, unit='%', is_active=1):
        """
        更新自定义监控指标
        
        Args:
            metric_id: 指标ID
            metric_name: 指标名称
            metric_description: 指标描述
            command: 执行命令
            unit: 指标单位
            is_active: 是否激活
            
        Returns:
            成功返回True，失败返回False
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE custom_metrics
                SET metric_name = ?, metric_description = ?, command = ?, unit = ?, is_active = ?
                WHERE id = ?
            ''', (metric_name, metric_description, command, unit, is_active, metric_id))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return False
    
    def delete_custom_metric(self, metric_id):
        """
        删除自定义监控指标
        
        Args:
            metric_id: 指标ID
            
        Returns:
            成功返回True，失败返回False
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 先删除关联的数据
            cursor.execute('DELETE FROM custom_metric_data WHERE metric_id = ?', (metric_id,))
            # 再删除指标
            cursor.execute('DELETE FROM custom_metrics WHERE id = ?', (metric_id,))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return False
    
    def get_all_custom_metrics(self):
        """
        获取所有自定义监控指标
        
        Returns:
            自定义监控指标列表
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, metric_name, metric_description, command, unit, is_active, created_at, updated_at FROM custom_metrics')
            metrics = cursor.fetchall()
            
            conn.close()
            return metrics
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return []
    
    def get_custom_metric(self, metric_id):
        """
        获取指定ID的自定义监控指标
        
        Args:
            metric_id: 指标ID
            
        Returns:
            自定义监控指标，不存在返回None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, metric_name, metric_description, command, unit, is_active, created_at, updated_at FROM custom_metrics WHERE id = ?', (metric_id,))
            metric = cursor.fetchone()
            
            conn.close()
            return metric
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return None
    
    def save_custom_metric_data(self, metric_id, ip, value):
        """
        保存自定义监控指标数据
        
        Args:
            metric_id: 指标ID
            ip: 主机IP
            value: 指标值
            
        Returns:
            成功返回True，失败返回False
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            check_time = datetime.now(self.shanghai_tz).strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT INTO custom_metric_data (metric_id, ip, value, check_time)
                VALUES (?, ?, ?, ?)
            ''', (metric_id, ip, value, check_time))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return False
    
    def get_custom_metric_data(self, metric_id, ip, start_time, end_time, limit=1000):
        """
        获取自定义监控指标数据
        
        Args:
            metric_id: 指标ID
            ip: 主机IP
            start_time: 开始时间
            end_time: 结束时间
            limit: 返回记录的最大数量
            
        Returns:
            自定义监控指标数据列表
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = '''
                SELECT check_time, value FROM custom_metric_data 
                WHERE metric_id = ? AND ip = ? AND check_time BETWEEN ? AND ? 
                ORDER BY check_time ASC LIMIT ?
            '''
            
            cursor.execute(query, (metric_id, ip, start_time, end_time, limit))
            data = cursor.fetchall()
            
            conn.close()
            return data
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return []
    
    def get_custom_metric_statistics(self, metric_id, ip, start_time, end_time):
        """
        计算自定义监控指标的统计数据
        
        Args:
            metric_id: 指标ID
            ip: 主机IP
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            包含统计数据的字典：平均值、峰值、最小值、中位数、标准差
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 获取原始数据
            query = '''
                SELECT value FROM custom_metric_data 
                WHERE metric_id = ? AND ip = ? AND check_time BETWEEN ? AND ? 
                ORDER BY value ASC
            '''
            
            cursor.execute(query, (metric_id, ip, start_time, end_time))
            data = cursor.fetchall()
            
            if not data:
                conn.close()
                return {
                    'average': 0,
                    'peak': 0,
                    'minimum': 0,
                    'median': 0,
                    'std_dev': 0,
                    'count': 0
                }
            
            # 提取数值并过滤None值
            values = [row[0] for row in data if row[0] is not None]
            count = len(values)
            
            if count == 0:
                conn.close()
                return {
                    'average': 0,
                    'peak': 0,
                    'minimum': 0,
                    'median': 0,
                    'std_dev': 0,
                    'count': 0
                }
            
            # 计算基本统计数据
            import statistics
            
            average = sum(values) / count
            
            # 计算最小值、最大值和中位数时剔除使用率一直为0%的数据点
            non_zero_values = [v for v in values if v > 0]
            
            # 计算最大值（峰值）
            peak = max(non_zero_values) if non_zero_values else max(values)
            
            # 计算最小值
            minimum = min(non_zero_values) if non_zero_values else min(values)
            
            # 计算中位数
            median = statistics.median(non_zero_values) if non_zero_values else statistics.median(values)
            
            std_dev = statistics.stdev(values) if count > 1 else 0
            
            conn.close()
            return {
                'average': round(average, 2),
                'peak': round(peak, 2),
                'minimum': round(minimum, 2),
                'median': round(median, 2),
                'std_dev': round(std_dev, 2),
                'count': count
            }
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return {
                'average': 0,
                'peak': 0,
                'minimum': 0,
                'median': 0,
                'std_dev': 0,
                'count': 0
            }
        except Exception as e:
            print(f"计算统计数据时出错: {e}")
            return {
                'average': 0,
                'peak': 0,
                'minimum': 0,
                'median': 0,
                'std_dev': 0,
                'count': 0
            }

