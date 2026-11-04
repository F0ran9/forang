# forang-agent — FORANG 任务容器镜像：Kali 基座 + 常用渗透工具内置。
# 背景：kalilinux/kali-rolling 裸镜像仅 84 个包——curl/wget/python3/nc 全无，
# agent 每个任务都要现场 apt install（慢且依赖网络），离线时只能退回
# repeater_send。本镜像把常用工具烤进去，任务容器即开即用。
#
# 构建（国内加速）：
#   docker build -f forang-agent.Dockerfile -t forang-agent:latest \
#     --build-arg APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/kali .
# 平台会在镜像缺失且本文件存在时自动构建（见 taskcontainer.go ensureAgentImage）。
# 注意：安装链不加全链 || true——失败要炸出来，否则空镜像层被静默接受。

ARG APT_MIRROR=http://http.kali.org/kali
FROM kalilinux/kali-rolling:latest

ARG APT_MIRROR=http://http.kali.org/kali
RUN sed -i "s|http://http.kali.org/kali|${APT_MIRROR}|g" /etc/apt/sources.list || true \
    && apt-get update -o Acquire::Retries=3

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        python3 \
        python3-pip \
        netcat-openbsd \
        nmap \
        sqlmap \
        nikto \
        dirb \
        gobuster \
        whois \
        dnsutils \
        net-tools \
        iputils-ping \
        iproute2 \
        jq \
        zip \
        unzip \
        gzip \
        tar \
        git \
        openssl \
        openssh-client \
        sshpass \
        hydra \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir requests dirsearch

# 常用字典软链（dirb 自带 common.txt；rockyou 按需挂载）
ENV TERM=xterm LANG=C.UTF-8
