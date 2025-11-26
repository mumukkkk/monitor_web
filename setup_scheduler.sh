#!/bin/bash

echo 设置定时任务 - 服务器监控数据采集

# 设置变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/monitor_scheduler.py"
PYTHON_EXE=python3
CRON_FILE="$SCRIPT_DIR/monitor_cron.txt"
HOURLY_SCRIPT="$SCRIPT_DIR/run_hourly.sh"

# 检查Python是否安装
if ! command -v $PYTHON_EXE &> /dev/null; then
    echo "错误: 未找到Python3，请确保Python3已安装"
    exit 1
fi

# 检查脚本是否存在
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "错误: 未找到监控脚本 $SCRIPT_PATH"
    exit 1
fi

# 创建每小时运行一次的脚本
cat > "$HOURLY_SCRIPT" << EOF
#!/bin/bash
cd "$SCRIPT_DIR"
$PYTHON_EXE "$SCRIPT_PATH" --once
EOF

chmod +x "$HOURLY_SCRIPT"

# 创建cron任务
CRON_JOB="0 * * * * $HOURLY_SCRIPT"

# 创建临时cron文件
crontab -l > "$CRON_FILE" 2>/dev/null || echo "" > "$CRON_FILE"

# 检查是否已存在相同的任务
if grep -q "monitor_scheduler.py" "$CRON_FILE"; then
    echo "检测到已存在的监控定时任务，将被替换"
    # 删除旧的任务
    grep -v "monitor_scheduler.py" "$CRON_FILE" > "${CRON_FILE}.tmp" && mv "${CRON_FILE}.tmp" "$CRON_FILE"
fi

# 添加新的任务
echo "$CRON_JOB" >> "$CRON_FILE"

# 安装新的crontab
crontab "$CRON_FILE"

if [ $? -eq 0 ]; then
    echo "定时任务设置成功！"
    echo "监控数据将每小时采集一次"
    echo ""
    echo "您可以使用以下命令管理任务："
    echo "  查看任务: crontab -l"
    echo "  编辑任务: crontab -e"
    echo ""
    echo "日志文件将保存在: $SCRIPT_DIR/monitor.log"
else
    echo "错误: 设置定时任务失败"
    exit 1
fi

# 清理临时文件
rm -f "$CRON_FILE"

