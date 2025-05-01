#!/bin/bash

# T3RN桥接机器人一键安装和启动脚本

echo "=== T3RN桥接机器人安装脚本 ==="

# 检查Python版本（需要3.8+）
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
if [[ -z "$PYTHON_VERSION" ]]; then
    echo "错误：未找到Python3！请安装Python 3.8或更高版本。"
    exit 1
fi

PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
if [[ $PYTHON_MAJOR -lt 3 || ($PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 8) ]]; then
    echo "错误：Python版本过低！需要Python 3.8或更高版本，当前版本：$PYTHON_VERSION"
    exit 1
fi
echo "Python版本：$PYTHON_VERSION"

# 安装pip（如果未安装）
if ! command -v pip3 &> /dev/null; then
    echo "安装pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3 get-pip.py
    rm get-pip.py
fi

# 安装依赖
echo "安装Python依赖..."
pip3 install loguru web3 requests --quiet
if [[ $? -ne 0 ]]; then
    echo "错误：安装依赖失败！请检查网络连接或pip配置。"
    exit 1
fi
echo "依赖安装完成。"

# 下载必要文件
echo "下载必要文件..."
BASE_URL="https://raw.githubusercontent.com/yinghao888/magebnb/main"

# 下载 t3rn_bridge.py
if [[ ! -f "t3rn_bridge.py" ]]; then
    wget -O t3rn_bridge.py $BASE_URL/t3rn_bridge.py
    if [[ $? -ne 0 ]]; then
        echo "错误：下载 t3rn_bridge.py 失败！"
        exit 1
    fi
    sed -i 's/\r//' t3rn_bridge.py
    echo "已下载 t3rn_bridge.py"
else
    echo "t3rn_bridge.py 已存在，跳过下载。"
fi

# 下载 utils.py
if [[ ! -f "utils.py" ]]; then
    wget -O utils.py $BASE_URL/utils.py
    if [[ $? -ne 0 ]]; then
        echo "错误：下载 utils.py 失败！"
        exit 1
    fi
    sed -i 's/\r//' utils.py
    echo "已下载 utils.py"
else
    echo "utils.py 已存在，跳过下载。"
fi

# 创建或下载 config.json
if [[ ! -f "config.json" ]]; then
    wget -O config.json $BASE_URL/config.json
    if [[ $? -ne 0 ]]; then
        echo "创建默认配置文件 config.json..."
        cat > config.json << EOL
{
  "api": {
    "base_url": "https://api.unlock3d.t3rn.io",
    "timeout": 30
  },
  "chains": {
    "base_sepolia": {
      "rpc_url": "https://sepolia.base.org",
      "bridge_contract": "0xYourBridgeContractAddress",
      "api_name": "base_sepolia",
      "gas_price_gwei": 1.5,
      "gas_limit": 150000
    },
    "optimism_sepolia": {
      "rpc_url": "https://sepolia.optimism.io",
      "bridge_contract": "0xYourBridgeContractAddress",
      "api_name": "optimism_sepolia",
      "gas_price_gwei": 1.5,
      "gas_limit": 150000
    }
  },
  "bridge": {
    "repeat_count": 1,
    "amount": {
      "min": 0.01,
      "max": 0.05
    },
    "wait_for_completion": true,
    "custom_flow": false
  },
  "delay": {
    "between_bridges": 30,
    "between_repeats": 60
  },
  "threads": 5,
  "use_proxy": false,
  "retries": {
    "max_attempts": 3,
    "backoff_factor": 2,
    "initial_wait": 1
  }
}
EOL
        echo "已创建 config.json。请根据需要编辑文件中的桥接合约地址和其他配置。"
    else
        sed -i 's/\r//' config.json
        echo "已下载 config.json"
    fi
else
    echo "config.json 已存在，跳过创建/下载。"
fi

# 创建私钥文件
if [[ ! -f "pk.txt" ]]; then
    echo "创建私钥文件 pk.txt..."
    touch pk.txt
    echo "# 请在此文件中添加您的私钥（每行一个）" > pk.txt
    echo "已创建 pk.txt，请在文件中添加私钥。"
else
    echo "pk.txt 已存在，跳过创建。"
fi

# 创建代理文件
if [[ ! -f "proxy.txt" ]]; then
    echo "创建代理文件 proxy.txt..."
    touch proxy.txt
    echo "# 请在此文件中添加您的代理（格式：user:pass@ip:port 或 ip:port，每行一个）" > proxy.txt
    echo "已创建 proxy.txt，如果需要使用代理，请在文件中添加代理地址。"
else
    echo "proxy.txt 已存在，跳过创建。"
fi

# 启动程序
echo "启动 T3RN桥接机器人..."
python3 t3rn_bridge.py
if [[ $? -ne 0 ]]; then
    echo "错误：启动程序失败！请检查 Python 脚本和配置文件。"
    exit 1
fi

echo "程序已退出。"
