FROM python:3.9-slim
WORKDIR /app

# 使用清华源加速
RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources || \
    sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends sshpass
COPY requirements.txt .

# 使用清华PyPI源安装Python依赖
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN mkdir -p /app/data
RUN mkdir -p /app/logs

EXPOSE 80

CMD ["python", "init.py"]
