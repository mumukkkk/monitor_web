#!/usr/bin/env python3
import os
import subprocess
import time
from datetime import datetime

# 导入自定义模块
from database_utils import DatabaseUtils
from privacy import decrypt_password
from monitor_config import MONITOR_INTERVAL, ANSIBLE_TIMEOUT, NETWORK_INTERFACE, CLEANUP_DAYS, ENABLE_AUTO_CLEANUP
from logger import MonitorLogger

class MonitorScheduler:
    def __init__(self):
        self.db = DatabaseUtils()
        self.logger = MonitorLogger()
    
    def collect_monitoring_data(self):
        """采集监控数据"""
        hosts = self.db.get_all_hosts()
        
        if not hosts:
            self.logger.warning("未找到任何主机，请先添加主机")
            return
        
        self.logger.info(f"开始采集 {len(hosts)} 个主机的监控数据")
        
        for host in hosts:
            ip, user, encrypted_password, port, _ = host
            
            # 解密密码
            password = decrypt_password(encrypted_password)
            if not password:
                self.logger.warning(f"无法解密密码 for {ip}, 跳过")
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
ansible_ssh_timeout={ANSIBLE_TIMEOUT}
"""
                
                with open('ansible_inventory', 'w') as f:
                    f.write(inventory_content)
                
                # 执行ping命令检查上线情况
                ping_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "ping"]
                result = subprocess.run(ping_cmd, capture_output=True, text=True)
                output = result.stdout.strip()
                
                if "SUCCESS" in output and "pong" in output:
                    self.logger.info(f"{ip} | 成功响应")
                    is_online = 1
                    
                    # 采集系统指标
                    cpu_usage = self._get_cpu_usage(ip)
                    memory_usage = self._get_memory_usage(ip)
                    disk_usage = self._get_disk_usage(ip)
                    network_rx, network_tx = self._get_network_usage(ip)
                    
                    self.logger.info(f"采集到 {ip} 的数据: CPU={cpu_usage:.2f}%, 内存={memory_usage:.2f}%, 磁盘={disk_usage:.2f}%")
                    
                    # 保存到数据库
                    self.db.save_monitoring_data(ip, cpu_usage, memory_usage, disk_usage, is_online, network_rx, network_tx)
                    
                else:
                    self.logger.warning(f"{ip} | 未成功响应: {output}")
                    # 保存离线状态，其他指标设为0
                    is_online = 0
                    self.db.save_monitoring_data(ip, 0.0, 0.0, 0.0, is_online, 0.0, 0.0)
                    
            except Exception as e:
                self.logger.error(f"采集 {ip} 数据时出错: {e}")
                # 保存错误状态
                self.db.save_monitoring_data(ip, 0.0, 0.0, 0.0, 0, 0.0, 0.0)
            
            finally:
                # 删除临时文件
                try:
                    os.remove('ansible_inventory')
                except:
                    pass
        
        self.logger.info(f"{datetime.now()}: 监控数据采集完成")
    
    def _get_cpu_usage(self, ip):
        """获取CPU使用率"""
        try:
            cpu_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell", 
                      "-a", "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'"]
            cpu_result = subprocess.run(cpu_cmd, capture_output=True, text=True)
            cpu_output = cpu_result.stdout.strip().split('\n')[-1]
            return float(cpu_output) if cpu_result.returncode == 0 and cpu_output.replace('.', '').isdigit() else 0.0
        except:
            return 0.0
    
    def _get_memory_usage(self, ip):
        """获取内存使用率"""
        try:
            memory_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell",  
                          "-a", "free | grep Mem | awk '{print $3/$2 * 100.0}'"]
            memory_result = subprocess.run(memory_cmd, capture_output=True, text=True)
            memory_output = memory_result.stdout.strip().split('\n')[-1]
            return float(memory_output) if memory_result.returncode == 0 and memory_output.replace('.', '').isdigit() else 0.0
        except:
            return 0.0
    
    def _get_disk_usage(self, ip):
        """获取磁盘使用率"""
        try:
            disk_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell", 
                        "-a", "df / | awk 'NR==2 {print $5}' | sed 's/%//'"]
            disk_result = subprocess.run(disk_cmd, capture_output=True, text=True)
            disk_output = disk_result.stdout.strip().split('\n')[-1]
            return float(disk_output) if disk_result.returncode == 0 and disk_output.replace('.', '').isdigit() else 0.0
        except:
            return 0.0
    
    def _get_network_usage(self, ip):
        """获取网络流量数据"""
        try:
            network_cmd = ["ansible", ip, "-i", "ansible_inventory", "-m", "shell", 
                          "-a", f"cat /proc/net/dev | grep -E '({NETWORK_INTERFACE}|ens|enp)' | head -1 | awk '{{print $2\" \"$10}}'"]
            network_result = subprocess.run(network_cmd, capture_output=True, text=True)
            network_output = network_result.stdout.strip()
            
            if network_result.returncode == 0 and network_output:
                # 处理Ansible输出，提取数字部分
                lines = network_output.split('\n')
                # 取最后一行，应该是数字
                last_line = lines[-1].strip()
                
                # 检查是否是数字行
                if last_line.replace(' ', '').isdigit():
                    rx_bytes, tx_bytes = map(int, last_line.split())
                    
                    # 计算网络流量（转换为MB）
                    network_rx = rx_bytes / 1024 / 1024  # 转换为MB
                    network_tx = tx_bytes / 1024 / 1024  # 转换为MB
                    
                    self.logger.debug(f"采集到 {ip} 的网络流量: RX={network_rx:.2f}MB, TX={network_tx:.2f}MB")
                    return network_rx, network_tx
                else:
                    self.logger.warning(f"采集 {ip} 网络流量数据失败：输出格式不正确")
                    return 0.0, 0.0
            else:
                self.logger.warning(f"采集 {ip} 网络流量数据失败：命令执行失败")
                return 0.0, 0.0
        except Exception as e:
            self.logger.error(f"采集 {ip} 网络流量数据时出错: {e}")
            return 0.0, 0.0
    
    def run_once(self):
        """运行一次数据采集"""
        self.collect_monitoring_data()
    
    def run_continuous(self):
        """连续运行监控"""
        self.logger.info("启动连续监控模式")
        self.logger.info(f"采集间隔: {MONITOR_INTERVAL} 秒")
        
        # 如果启用自动清理，先执行一次清理
        if ENABLE_AUTO_CLEANUP:
            self.logger.info(f"自动清理 {CLEANUP_DAYS} 天前的数据")
            self.db.cleanup_old_data(CLEANUP_DAYS)
        
        try:
            while True:
                self.logger.info(f"{datetime.now()}: 开始采集监控数据")
                self.collect_monitoring_data()
                self.logger.info(f"{datetime.now()}: 监控数据采集完成，等待{MONITOR_INTERVAL}秒")
                time.sleep(MONITOR_INTERVAL)
        except KeyboardInterrupt:
            self.logger.info("监控已停止")
        except Exception as e:
            self.logger.error(f"监控过程中出错: {e}")

if __name__ == "__main__":
    import sys
    
    scheduler = MonitorScheduler()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        # 运行一次采集模式
        scheduler.run_once()
    else:
        # 连续监控模式
        scheduler.run_continuous()

