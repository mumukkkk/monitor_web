@echo off
echo 设置定时任务 - 服务器监控数据采集

:: 设置变量
set TASK_NAME=ServerMonitorDataCollection
set SCRIPT_PATH=%~dp0monitor_scheduler.py
set PYTHON_EXE=python
set HOURLY=%~dp0run_hourly.bat

:: 检查Python是否安装
%PYTHON_EXE% --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请确保Python已安装并添加到PATH
    pause
    exit /b 1
)

:: 检查脚本是否存在
if not exist "%SCRIPT_PATH%" (
    echo 错误: 未找到监控脚本 %SCRIPT_PATH%
    pause
    exit /b 1
)

:: 创建每小时运行一次的批处理文件
echo @echo off > "%HOURLY%"
echo cd /d "%~dp0" >> "%HOURLY%"
echo %PYTHON_EXE% "%SCRIPT_PATH%" --once >> "%HOURLY%"

:: 删除现有任务（如果存在）
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

:: 创建新的定时任务 - 每小时运行一次
echo 正在创建定时任务...
schtasks /create /tn "%TASK_NAME%" /tr "%HOURLY%" /sc hourly /f

if errorlevel 1 (
    echo 错误: 创建定时任务失败，请以管理员身份运行此脚本
    pause
    exit /b 1
)

echo 定时任务创建成功！
echo 监控数据将每小时采集一次
echo.
echo 您可以使用以下命令管理任务：
echo   查看任务: schtasks /query /tn "%TASK_NAME%"
echo   手动运行: schtasks /run /tn "%TASK_NAME%"
echo   删除任务: schtasks /delete /tn "%TASK_NAME%" /f
echo.
pause

