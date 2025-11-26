# 监控配置文件
import os

# 数据库配置
DATABASE_PATH = os.environ.get('MONITOR_DB_PATH', 'server_monitor.db')

# 监控配置
MONITOR_INTERVAL = int(os.environ.get('MONITOR_INTERVAL', 30))  # 默认5分钟采集一次
LOG_LEVEL = os.environ.get('MONITOR_LOG_LEVEL', 'INFO')  # DEBUG, INFO, WARNING, ERROR
LOG_FILE = os.environ.get('MONITOR_LOG_FILE', 'monitor.log')

# 数据清理配置
CLEANUP_DAYS = int(os.environ.get('MONITOR_CLEANUP_DAYS', 30))  # 保留30天的数据
ENABLE_AUTO_CLEANUP = os.environ.get('MONITOR_AUTO_CLEANUP', 'True').lower() == 'true'

# Ansible配置
ANSIBLE_TIMEOUT = int(os.environ.get('ANSIBLE_TIMEOUT', 30))  # Ansible连接超时时间（秒）

# 网络流量计算配置
NETWORK_INTERFACE = os.environ.get('NETWORK_INTERFACE', 'eth0')  # 默认网络接口

