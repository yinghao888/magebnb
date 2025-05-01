import time
import os
import sys
import random
import threading
import queue
import traceback
import signal
import json
import requests
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.providers.rpc import HTTPProvider
from eth_account import Account
from hexbytes import HexBytes
from urllib.parse import urlparse
from datetime import datetime
from loguru import logger
import functools
import re
from utils import display_banner, display_processing_animation

# 线程本地存储
_thread_local = threading.local()

# 常量定义
API_ENDPOINTS = {
    "price": "/prices/usd/{chain}/{token}/{amount}",
    "estimate": "/estimate",
    "order": "/order/{order_id}"
}

TX_STATUS = {
    "PLACED": "已提交",
    "PENDING": "等待中",
    "BID": "已竞价",
    "EXECUTED": "已执行",
    "ATTESTED": "已认证",
    "CLAIMED": "已领取",
    "CLAIMED_INSURANCE": "已领取保险金",
    "EXPIRED": "已过期",
    "PENDING_REFUND": "等待退款",
    "ATTESTED_REFUND": "已认证退款",
    "CLAIMED_REFUND": "已领取退款",
    "FAILED": "失败"
}

STATUS_DESCRIPTIONS = {
    "已提交": "订单已收到并已进入队列，等待处理。",
    "等待中": "订单现在在第3层网络上，等待竞价。",
    "已竞价": "订单现在已被执行者竞价。它已准备好执行。",
    "已执行": "订单已被执行。",
    "已认证": "订单已被认证。",
    "已领取": "执行此订单的奖励已被执行者领取。",
    "已领取保险金": "此订单的保险金已被领取，交易已完成。",
    "已过期": "订单超过30分钟并已过期。将检查它是否已执行或有资格获得退款。",
    "等待退款": "订单未能及时完成。下订单的账户尚未请求退款。",
    "已认证退款": "退款已被认证。",
    "已领取退款": "订单未能及时完成。已为下订单的账户发起退款。",
    "失败": "订单处理失败。"
}

SUCCESS_STATUSES = ["已执行", "已认证", "已领取", "已领取保险金"]
REFUND_STATUSES = ["已过期", "等待退款", "已认证退款", "已领取退款"]
FAILED_STATUSES = ["失败"]

DEFAULT_HEADERS = {
    "accept": "*/*",
    "content-type": "application/json",
    "origin": "https://unlock3d.t3rn.io",
    "referer": "https://unlock3d.t3rn.io/"
}

DEFAULT_TIMEOUT = 30
DEFAULT_GAS_LIMIT = 135000

# 日志设置
def setup_logger():
    """设置日志记录器并使用自定义格式。"""
    log_format = (
        "<green>{time:DD/MM/YYYY - HH:mm:ss}</green>"
        "{extra[wallet]: <14} | "
        "<level>{level: <8}</level> | "
        "<cyan>{module: <15}</cyan> | "
        "<level>{message}</level>"
    )
    
    logger.remove()
    logger.add(sys.stdout, format=log_format, level="INFO", colorize=True)
    
    os.makedirs("logs", exist_ok=True)
    log_file = f"logs/t3rn_bridge_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger.add(log_file, format=log_format, level="DEBUG", rotation="10 MB", retention="1 week")
    
    _thread_local.wallet = ""
    logger.configure(extra={"wallet": ""})
    return logger

def get_masked_address(address):
    """获取掩码地址（前6个和后4个字符）。"""
    if not address or len(address) < 10:
        return address
    return f"{address[:6]}...{address[-4:]}"

def set_wallet_context(address):
    """设置线程本地日志器上下文中的钱包地址。"""
    masked = get_masked_address(address)
    _thread_local.wallet = f" - {masked}"
    return masked

def log():
    """获取线程特定的日志器。"""
    wallet_context = getattr(_thread_local, 'wallet', "")
    return logger.bind(wallet=wallet_context)

# 重试装饰器
def retry_with_backoff(func):
    """带指数退避的重试装饰器。"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        config = args[0].config.get('retries', {}) if args and hasattr(args[0], 'config') else {}
        max_attempts = config.get('max_attempts', 3)
        backoff_factor = config.get('backoff_factor', 2)
        initial_wait = config.get('initial_wait', 1)
        
        last_exception = None
        attempt = 0
        
        while attempt < max_attempts:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                attempt += 1
                last_exception = e
                error_str = str(e)
                if "RO#7" in error_str:
                    raise
                if attempt >= max_attempts:
                    log().error(f"所有 {max_attempts} 次重试尝试均失败")
                    raise last_exception
                wait_time = initial_wait * (backoff_factor ** (attempt - 1))
                wait_time = wait_time * (1 + random.uniform(-0.1, 0.1))
                log().warning(f"尝试 {attempt} 失败: {str(e)}。将在 {wait_time:.2f} 秒后重试...")
                time.sleep(wait_time)
    return wrapper

# 线程安全管理
class SessionManager:
    """管理线程特定的HTTP会话。"""
    
    @staticmethod
    def get_session(proxy=None):
        """获取线程特定的请求会话。"""
        if not hasattr(_thread_local, 'http_session'):
            log().debug(f"为线程 {threading.get_ident()} 创建新的HTTP会话")
            _thread_local.http_session = requests.Session()
            _thread_local.http_session.headers.update(DEFAULT_HEADERS)
        if proxy:
            _thread_local.http_session.proxies = proxy
        return _thread_local.http_session

    @staticmethod
    def close_sessions():
        """关闭当前线程的会话。"""
        if hasattr(_thread_local, 'http_session'):
            log().debug(f"关闭线程 {threading.get_ident()} 的HTTP会话")
            _thread_local.http_session.close()
            delattr(_thread_local, 'http_session')

class Web3ConnectionManager:
    """管理线程特定的Web3连接。"""
    
    @staticmethod
    def get_web3_connections():
        """获取线程特定的Web3连接字典。"""
        if not hasattr(_thread_local, 'web3_connections'):
            log().debug(f"为线程 {threading.get_ident()} 创建新的Web3连接容器")
            _thread_local.web3_connections = {}
        return _thread_local.web3_connections
    
    @staticmethod
    def close_connections():
        """清理当前线程的Web3连接。"""
        if hasattr(_thread_local, 'web3_connections'):
            log().debug(f"清理线程 {threading.get_ident()} 的Web3连接")
            delattr(_thread_local, 'web3_connections')

# 代理管理
class ProxyManager:
    """管理代理配置。"""
    
    def __init__(self, use_proxy):
        self.use_proxy = use_proxy
        self.proxies = []
        if use_proxy:
            self._load_proxies()
    
    def _load_proxies(self):
        """从proxy.txt文件加载代理。"""
        try:
            if not os.path.exists("proxy.txt"):
                log().warning("未找到proxy.txt文件！将在不使用代理的情况下运行。")
                self.use_proxy = False
                return
            with open("proxy.txt", "r") as file:
                self.proxies = [line.strip() for line in file.readlines() if line.strip() and not line.strip().startswith('#')]
            if not self.proxies:
                log().warning("在proxy.txt中未找到代理！将在不使用代理的情况下运行。")
                self.use_proxy = False
                return
            log().info(f"已加载 {len(self.proxies)} 个代理")
        except Exception as e:
            log().error(f"加载代理时出错: {str(e)}")
            self.use_proxy = False
    
    def format_proxy_url(self, proxy_url):
        """格式化代理URL。"""
        if not any(proxy_url.startswith(p) for p in ["http://", "https://", "socks4://", "socks5://"]):
            proxy_url = f"http://{proxy_url}" if '@' in proxy_url and ':' in proxy_url else f"http://{proxy_url}"
        return proxy_url
    
    def get_proxy(self, index):
        """获取给定索引的代理配置。"""
        if not self.use_proxy or not self.proxies:
            return None, None
        proxy_index = index % len(self.proxies)
        raw_proxy_url = self.proxies[proxy_index]
        formatted_proxy_url = self.format_proxy_url(raw_proxy_url)
        proxy_dict = {"http": formatted_proxy_url, "https": formatted_proxy_url}
        return proxy_dict, formatted_proxy_url

# Web3服务
class ProxiedHTTPProvider(HTTPProvider):
    """支持代理的自定义HTTP提供者。"""
    
    def __init__(self, endpoint_uri, proxy_url=None, request_kwargs=None, **kwargs):
        self.proxy_url = proxy_url
        if request_kwargs is None:
            request_kwargs = {}
        if 'timeout' not in request_kwargs:
            request_kwargs['timeout'] = 30
        super().__init__(endpoint_uri, request_kwargs=request_kwargs, **kwargs)
    
    def make_request(self, method, params):
        request_data = self.encode_rpc_request(method, params)
        session = requests.Session()
        if self.proxy_url:
            session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        timeout = self._request_kwargs.get('timeout', 30)
        raw_response = session.post(self.endpoint_uri, data=request_data, headers=self.get_request_headers(), timeout=timeout)
        return self.decode_rpc_response(raw_response.content)

class Web3Service:
    """用于与Web3交互的服务。"""
    
    def __init__(self, private_key, config, proxy=None):
        self.private_key = private_key
        self.config = config
        if isinstance(proxy, tuple) and len(proxy) == 2:
            self.proxy_dict, self.proxy_url = proxy
        else:
            self.proxy_dict = proxy
            self.proxy_url = None if proxy is None else proxy.get("http") if isinstance(proxy, dict) else None
        self.account = Account.from_key(private_key)
    
    def get_account_address(self):
        """获取账户地址。"""
        return self.account.address
    
    def get_web3(self, chain_name):
        """获取指定链的Web3连接。"""
        web3_connections = Web3ConnectionManager.get_web3_connections()
        if chain_name in web3_connections:
            return web3_connections[chain_name]
        chain_config = self.config["chains"].get(chain_name)
        if not chain_config:
            raise ValueError(f"未找到链 {chain_name} 的配置")
        rpc_url = chain_config["rpc_url"]
        if self.proxy_url:
            provider = ProxiedHTTPProvider(rpc_url, proxy_url=self.proxy_url, request_kwargs={'timeout': 30})
            web3 = Web3(provider)
        else:
            web3 = Web3(Web3.HTTPProvider(rpc_url))
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        if not web3.is_connected():
            log().error(f"无法连接到 {chain_name} 的RPC：{rpc_url}")
            raise ConnectionError(f"无法连接到 {chain_name} 的RPC")
        web3_connections[chain_name] = web3
        return web3
    
    @retry_with_backoff
    def get_gas_price(self, chain_name):
        """获取当前gas价格。"""
        web3 = self.get_web3(chain_name)
        gas_price = web3.eth.gas_price
        log().debug(f"{chain_name} 上的当前gas价格: {gas_price} wei")
        return gas_price
    
    @retry_with_backoff
    def estimate_gas(self, chain_name, tx_params):
        """估计交易所需的gas。"""
        web3 = self.get_web3(chain_name)
        tx_for_estimation = {k: v for k, v in tx_params.items() if k != 'gas'}
        try:
            estimated_gas = web3.eth.estimate_gas(tx_for_estimation)
            gas_with_buffer = int(estimated_gas * 1.1)
            log().debug(f"{chain_name} 上估计的gas: {estimated_gas}（带缓冲: {gas_with_buffer}）")
            return gas_with_buffer
        except Exception as e:
            log().error(f"在 {chain_name} 上估计gas时出错: {str(e)}")
            raise
    
    @retry_with_backoff
    def get_nonce(self, chain_name):
        """获取账户当前nonce。"""
        web3 = self.get_web3(chain_name)
        nonce = web3.eth.get_transaction_count(self.account.address)
        log().debug(f"{chain_name} 上的当前nonce: {nonce}")
        return nonce
    
    @retry_with_backoff
    def get_balance(self, chain_name):
        """获取账户余额。"""
        web3 = self.get_web3(chain_name)
        balance_wei = web3.eth.get_balance(self.account.address)
        balance_eth = web3.from_wei(balance_wei, 'ether')
        log().info(f"{chain_name} 上的余额: {balance_eth} ETH")
        return balance_wei
    
    @retry_with_backoff
    def get_transaction_receipt(self, chain_name, tx_hash):
        """获取交易收据。"""
        web3 = self.get_web3(chain_name)
        try:
            if isinstance(tx_hash, str) and not tx_hash.startswith('0x'):
                tx_hash = '0x' + tx_hash
            receipt = web3.eth.get_transaction_receipt(tx_hash)
            return receipt
        except Exception as e:
            log().error(f"在 {chain_name} 上获取交易收据时出错: {str(e)}")
            return None
    
    @retry_with_backoff
    def send_transaction(self, chain_name, transaction):
        """发送交易。"""
        web3 = self.get_web3(chain_name)
        try:
            signed_tx = web3.eth.account.sign_transaction(transaction, private_key=self.private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            if isinstance(tx_hash, HexBytes):
                tx_hash = tx_hash.hex()
            log().info(f"交易已发送至 {chain_name}，哈希: {tx_hash}")
            return tx_hash
        except Exception as e:
            log().error(f"在 {chain_name} 上发送交易时出错: {str(e)}")
            if "nonce too low" in str(e).lower():
                log().warning("nonce太低。可能另一个交易使用了相同的nonce。")
            elif "insufficient funds" in str(e).lower():
                log().warning("资金不足。请确保账户有足够的ETH支付交易费用。")
            raise
    
    @retry_with_backoff
    def verify_transaction(self, chain_name, tx_hash, timeout=120):
        """验证交易是否已确认。"""
        log().info(f"验证 {chain_name} 上的交易：{tx_hash}")
        start_time = time.time()
        web3 = self.get_web3(chain_name)
        if isinstance(tx_hash, str) and not tx_hash.startswith('0x'):
            tx_hash = '0x' + tx_hash
        while time.time() - start_time < timeout:
            try:
                receipt = web3.eth.get_transaction_receipt(tx_hash)
                if receipt is not None:
                    if receipt.status == 1:
                        log().success(f"{chain_name} 上的交易已确认")
                        return True
                    else:
                        log().error(f"{chain_name} 上的交易失败")
                        return False
            except Exception as e:
                log().error(f"检查交易状态时出错: {str(e)}")
            time.sleep(5)
        log().warning(f"验证交易状态超时（{timeout}秒）")
        return False

# 桥接服务
status_lock = threading.RLock()

class BridgeService:
    """用于与t3rn桥交互的服务。"""
    
    def __init__(self, private_key, config, proxy=None):
        self.private_key = private_key
        self.config = config
        if isinstance(proxy, tuple) and len(proxy) == 2:
            self.proxy_dict, self.proxy_url = proxy
        else:
            self.proxy_dict = proxy
            self.proxy_url = None if proxy is None else proxy.get("http") if isinstance(proxy, dict) else None
        self.web3_service = Web3Service(private_key, config, proxy)
        self.api_base_url = config["api"]["base_url"]
        self.wallet_address = self.web3_service.get_account_address()
    
    def get_wallet_address(self):
        """获取钱包地址。"""
        return self.wallet_address
    
    def get_native_asset_for_chain(self, chain_name):
        """获取给定链的原生资产符号。"""
        chain_to_asset = {"monad_testnet": "mon", "sei_testnet": "sei"}
        return chain_to_asset.get(chain_name, "eth")
    
    @retry_with_backoff
    def get_price(self, chain, token, amount_wei):
        """获取代币的美元价格。"""
        url = f"{self.api_base_url}{API_ENDPOINTS['price'].format(chain=chain, token=token, amount=amount_wei)}"
        try:
            session = SessionManager.get_session(self.proxy_dict)
            response = session.get(url, timeout=self.config["api"]["timeout"])
            response.raise_for_status()
            return float(response.text)
        except requests.RequestException as e:
            log().error(f"获取价格时出错: {str(e)}")
            raise
    
    @retry_with_backoff
    def estimate_bridge(self, from_chain, to_chain, amount_wei):
        """估算桥接交易。"""
        url = f"{self.api_base_url}{API_ENDPOINTS['estimate']}"
        from_chain_config = self.config["chains"][from_chain]
        to_chain_config = self.config["chains"][to_chain]
        from_asset = self.get_native_asset_for_chain(from_chain)
        to_asset = self.get_native_asset_for_chain(to_chain)
        payload = {
            "fromAsset": from_asset,
            "toAsset": to_asset,
            "fromChain": from_chain_config["api_name"],
            "toChain": to_chain_config["api_name"],
            "amountWei": amount_wei,
            "executorTipUSD": 0,
            "overpayOptionPercentage": 0,
            "spreadOptionPercentage": 0
        }
        log().debug(f"估算负载: {payload}")
        try:
            session = SessionManager.get_session(self.proxy_dict)
            response = session.post(url, json=payload, timeout=self.config["api"]["timeout"])
            response.raise_for_status()
            estimate_data = response.json()
            log().debug(f"估算响应: {json.dumps(estimate_data, indent=2)}")
            return estimate_data
        except requests.RequestException as e:
            log().error(f"估算桥接时出错: {str(e)}")
            raise
    
    def bridge(self, from_chain, to_chain, amount):
        """执行桥接操作。"""
        amount = round(amount, 5)
        from_asset = self.get_native_asset_for_chain(from_chain)
        to_asset = self.get_native_asset_for_chain(to_chain)
        log().info(f"准备将 {amount} {from_asset.upper()} 从 {from_chain} 桥接到 {to_chain} ({to_asset.upper()})")
        amount_wei = Web3.to_wei(amount, 'ether')
        amount_wei_str = str(amount_wei)
        from_chain_config = self.config["chains"][from_chain]
        to_chain_config = self.config["chains"][to_chain]
        usd_price = self.get_price(from_chain_config["api_name"], from_asset, amount_wei_str)
        log().info(f"当前 {from_asset.upper()} 价值: ${usd_price:.2f}")
        estimate = self.estimate_bridge(from_chain, to_chain, amount_wei_str)
        method_id = "0x56591d59"
        bridge_contract = from_chain_config["bridge_contract"]
        dest_chain = to_chain_config["api_name"]
        dest_chain_bytes = dest_chain.encode('utf-8').ljust(32, b'\0')
        dest_chain_hex = dest_chain_bytes.hex()
        target_address = self.wallet_address.lower()[2:]
        target_address_padded = '0' * (64 - len(target_address)) + target_address
        if "estimatedReceivedAmountWei" in estimate and estimate["estimatedReceivedAmountWei"].get("hex"):
            amount_hex = estimate["estimatedReceivedAmountWei"]["hex"][2:]
        else:
            amount_hex = hex(amount_wei)[2:]
        amount_padded = '0' * (64 - len(amount_hex)) + amount_hex
        zeros_padding = '0' * 64
        if "maxReward" in estimate and estimate["maxReward"].get("hex"):
            max_reward_hex = estimate["maxReward"]["hex"][2:]
        else:
            max_reward_hex = hex(amount_wei)[2:]
        max_reward_padded = '0' * (64 - len(max_reward_hex)) + max_reward_hex
        calldata = (
            method_id +
            dest_chain_hex +
            target_address_padded +
            zeros_padding +
            amount_padded +
            max_reward_padded
        )
        tx = {
            'to': Web3.to_checksum_address(bridge_contract),
            'value': amount_wei,
            'gas': self.config["chains"][from_chain].get("gas_limit", 150000),
            'gasPrice': Web3.to_wei(from_chain_config.get("gas_price_gwei", 1.5), 'gwei'),
            'nonce': self.web3_service.get_nonce(from_chain),
            'data': calldata
        }
        log().debug(f"交易数据: {calldata}")
        try:
            tx_hash = self.web3_service.send_transaction(from_chain, tx)
            if tx_hash:
                log().success(f"桥接交易已发送: {tx_hash}")
                order_id = self.extract_order_id_from_receipt(from_chain, tx_hash)
                if order_id:
                    log().info(f"已提取订单ID: {order_id}")
                    self.last_order_id = order_id
                else:
                    log().warning("无法提取订单ID，后续状态更新可能受限")
                return tx_hash
            else:
                log().error("发送桥接交易失败")
                return None
        except Exception as e:
            log().error(f"发送桥接交易时出错: {str(e)}")
            traceback.print_exc()
            return None
    
    @retry_with_backoff
    def get_order_status(self, order_id):
        """获取桥接订单状态。"""
        url = f"{self.api_base_url}{API_ENDPOINTS['order'].format(order_id=order_id)}"
        try:
            session = SessionManager.get_session(self.proxy_dict)
            response = session.get(url, timeout=self.config["api"]["timeout"])
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            log().error(f"获取订单状态时出错: {str(e)}")
            raise
    
    def extract_order_id_from_receipt(self, chain_name, tx_hash):
        """从交易收据中提取订单ID。"""
        max_attempts = 5
        delay_seconds = 2
        for attempt in range(max_attempts):
            try:
                receipt = self.web3_service.get_transaction_receipt(chain_name, tx_hash)
                if receipt and receipt.get('logs'):
                    if len(receipt['logs']) > 0 and len(receipt['logs'][0]['topics']) > 2:
                        order_bytes = receipt['logs'][0]['topics'][2]
                        order_id = order_bytes.hex() if isinstance(order_bytes, bytes) else order_bytes
                        if order_id.startswith('0x'):
                            order_id = order_id[2:]
                        if len(order_id) > 10:
                            return order_id
                    for log_entry in receipt['logs']:
                        if 'data' in log_entry and len(log_entry['data']) > 66:
                            possible_order_id = log_entry['data'][2:66]
                            if possible_order_id and all(c in '0123456789abcdefABCDEF' for c in possible_order_id):
                                return possible_order_id
                log().debug(f"尝试 {attempt+1}/{max_attempts} 未找到订单ID，等待然后重试...")
                time.sleep(delay_seconds)
            except Exception as e:
                log().error(f"尝试 {attempt+1}/{max_attempts} 从收据中提取订单ID时出错: {str(e)}")
                time.sleep(delay_seconds)
        log().warning(f"无法从交易 {tx_hash} 提取订单ID")
        return None
    
    def wait_for_completion(self, tx_hash, max_attempts=60, delay=5, timeout_minutes=15, source_chain=None):
        """等待桥接交易完成。"""
        timeout_seconds = timeout_minutes * 60
        start_time = time.time()
        end_time = start_time + timeout_seconds
        bridge_completed = False
        last_displayed_status = None
        already_had_pending_status = False
        max_delay = 30
        current_delay = delay
        log().info(f"等待桥接完成，最长 {timeout_minutes} 分钟...")
        order_id = getattr(self, 'last_order_id', None)
        if not order_id and source_chain:
            order_id = self.extract_order_id_from_receipt(source_chain, tx_hash)
            if order_id:
                self.last_order_id = order_id
                log().info(f"找到桥接订单ID: {order_id}")
            else:
                log().warning("无法提取订单ID，将使用替代状态检查")
        if order_id:
            attempt = 0
            while time.time() < end_time and attempt < max_attempts:
                try:
                    order_status = self.get_order_status(order_id)
                    if 'status' in order_status:
                        current_status = order_status['status']
                        with status_lock:
                            if current_status != last_displayed_status:
                                status_desc = STATUS_DESCRIPTIONS.get(current_status, f"状态代码：{current_status}")
                                log().info(f"桥接状态更新：{current_status} - {status_desc}")
                                last_displayed_status = current_status
                                current_delay = delay
                        if current_status in SUCCESS_STATUSES:
                            log().success(f"桥接成功完成，状态：{current_status}")
                            bridge_completed = True
                            break
                        elif current_status in FAILED_STATUSES:
                            log().error(f"桥接失败，状态：{current_status}")
                            return False
                        elif current_status in REFUND_STATUSES:
                            log().warning(f"桥接需要退款，状态：{current_status}")
                        if current_status == "等待中" and already_had_pending_status:
                            current_delay = min(current_delay * 1.5, max_delay)
                        if current_status == "等待中":
                            already_had_pending_status = True
                except Exception as e:
                    log().error(f"检查桥接状态时出错：{str(e)}")
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout_seconds:
                    log().warning(f"桥接状态检查超时（{timeout_minutes}分钟）")
                    return bridge_completed
                attempt += 1
                time.sleep(current_delay)
            if not bridge_completed and attempt >= max_attempts:
                log().warning(f"已达到最大状态检查尝试次数（{max_attempts}次）")
        else:
            log().info("使用替代方法检查桥接状态（无订单ID）")
            def check_destination_confirmation():
                time.sleep(300)
                if time.time() >= end_time:
                    return
                log().info("开始在目标链上检查存款。")
                log().info("请手动验证目标链上的资金。")
            confirmation_thread = threading.Thread(target=check_destination_confirmation, daemon=True)
            confirmation_thread.start()
            attempt = 0
            while time.time() < end_time and attempt < max_attempts:
                elapsed_minutes = (time.time() - start_time) / 60
                if attempt % 6 == 0:
                    log().info(f"等待桥接完成... 已经过 {elapsed_minutes:.1f} 分钟")
                attempt += 1
                time.sleep(delay)
            log().warning("无法确认桥接状态，请手动验证目标链上的资金。")
            return True
        return bridge_completed

# 配置管理
class ConfigManager:
    """管理应用程序配置。"""
    
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self):
        """加载配置文件。"""
        try:
            if not os.path.exists(self.config_path):
                logger.error(f"未找到配置文件 {self.config_path}！")
                raise FileNotFoundError(f"未找到配置文件 {self.config_path}！")
            with open(self.config_path, "r") as file:
                config = json.load(file)
            return config
        except json.JSONDecodeError:
            logger.error(f"配置文件 {self.config_path} 中的JSON无效")
            raise
        except Exception as e:
            logger.error(f"加载配置时出错: {str(e)}")
            raise
    
    def get_config(self):
        """获取配置。"""
        return self.config
    
    def get_chain_config(self, chain_name):
        """获取特定链的配置。"""
        chains = self.config.get("chains", {})
        chain_config = chains.get(chain_name)
        if not chain_config:
            logger.error(f"未找到链 {chain_name} 的配置！")
            raise ValueError(f"未找到链 {chain_name} 的配置！")
        return chain_config
    
    def get_api_config(self):
        """获取API配置。"""
        api_config = self.config.get("api", {})
        if not api_config:
            logger.error("未找到API配置！")
            raise ValueError("未找到API配置！")
        return api_config

# 交互式菜单
def display_menu():
    """显示交互式菜单。"""
    print("\n=== T3RN桥接机器人菜单 ===")
    print("1. 配置私钥")
    print("2. 配置代理")
    print("3. 查看当前配置")
    print("4. 运行桥接任务")
    print("5. 退出")
    print("=========================\n")
    return input("请输入选项 (1-5): ")

def configure_private_keys():
    """配置私钥。"""
    print("\n=== 配置私钥 ===")
    print("1. 从 pk.txt 加载私钥")
    print("2. 手动输入私钥")
    choice = input("请选择 (1-2): ")
    
    private_keys = []
    if choice == "1":
        try:
            with open("pk.txt", "r") as file:
                private_keys = [line.strip() for line in file.readlines() if line.strip() and not line.strip().startswith('#')]
            if not private_keys:
                print("pk.txt 文件为空！")
            else:
                print(f"已加载 {len(private_keys)} 个私钥。")
        except FileNotFoundError:
            print("未找到 pk.txt 文件！请确保文件存在。")
        except Exception as e:
            print(f"读取私钥时出错: {str(e)}")
    elif choice == "2":
        while True:
            key = input("请输入私钥 (输入空行完成): ").strip()
            if not key:
                break
            if key.startswith("0x"):
                key = key[2:]
            if len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
                private_keys.append(key)
            else:
                print("无效的私钥格式！私钥应为64位十六进制字符串。")
        if private_keys:
            with open("pk.txt", "w") as file:
                for key in private_keys:
                    file.write(key + "\n")
            print(f"已保存 {len(private_keys)} 个私钥到 pk.txt")
    else:
        print("无效选项！")
    return private_keys

def configure_proxies():
    """配置代理。"""
    print("\n=== 配置代理 ===")
    print("1. 从 proxy.txt 加载代理")
    print("2. 手动输入代理")
    print("3. 不使用代理")
    choice = input("请选择 (1-3): ")
    
    proxies = []
    use_proxy = False
    if choice == "1":
        try:
            with open("proxy.txt", "r") as file:
                proxies = [line.strip() for line in file.readlines() if line.strip() and not line.strip().startswith('#')]
            if not proxies:
                print("proxy.txt 文件为空！")
            else:
                print(f"已加载 {len(proxies)} 个代理。")
                use_proxy = True
        except FileNotFoundError:
            print("未找到 proxy.txt 文件！请确保文件存在。")
        except Exception as e:
            print(f"读取代理时出错: {str(e)}")
    elif choice == "2":
        while True:
            proxy = input("请输入代理 (格式: user:pass@ip:port 或 ip:port，输入空行完成): ").strip()
            if not proxy:
                break
            proxies.append(proxy)
        if proxies:
            with open("proxy.txt", "w") as file:
                for proxy in proxies:
                    file.write(proxy + "\n")
            print(f"已保存 {len(proxies)} 个代理到 proxy.txt")
            use_proxy = True
    elif choice == "3":
        print("已选择不使用代理。")
        use_proxy = False
    else:
        print("无效选项！")
    return proxies, use_proxy

def view_configuration(config, private_keys, proxies, use_proxy):
    """查看当前配置。"""
    print("\n=== 当前配置 ===")
    print("配置文件:")
    print(json.dumps(config, indent=2, ensure_ascii=False))
    print(f"\n私钥数量: {len(private_keys)}")
    print(f"代理数量: {len(proxies)}")
    print(f"是否使用代理: {'是' if use_proxy else '否'}")
    input("\n按回车键返回菜单...")

# 主程序
wallet_queue = queue.Queue()
shutdown_event = threading.Event()

def signal_handler(sig, frame):
    """处理Ctrl+C中断。"""
    logger.info("\n检测到键盘中断(Ctrl+C)。正在优雅地关闭...")
    shutdown_event.set()
    logger.info("等待线程终止（最多5秒）...")
    exit_timer = threading.Timer(5.0, force_exit)
    exit_timer.daemon = True
    exit_timer.start()

def force_exit():
    """强制退出程序。"""
    logger.error("等待线程终止超时。强制退出。")
    sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)

def read_private_keys():
    """读取私钥文件。"""
    try:
        with open("pk.txt", "r") as file:
            keys = [line.strip() for line in file.readlines() if line.strip() and not line.strip().startswith('#')]
        return keys
    except FileNotFoundError:
        return []
    except Exception as e:
        logger.error(f"读取私钥时出错: {str(e)}")
        return []

def process_wallet(wallet_info):
    """处理单个钱包的桥接流程。"""
    private_key = wallet_info["private_key"]
    index = wallet_info["index"]
    total_wallets = wallet_info["total_wallets"]
    proxy = wallet_info["proxy"]
    config_data = wallet_info["config"]
    
    try:
        bridge_service = BridgeService(private_key=private_key, config=config_data, proxy=proxy)
        wallet_address = bridge_service.get_wallet_address()
        masked_address = set_wallet_context(wallet_address)
        log().info(f"正在处理钱包 {masked_address} ({index+1}/{total_wallets})")
        wallet_timeout = 45 * 60
        wallet_start_time = time.time()
        
        for j in range(config_data["bridge"]["repeat_count"]):
            if shutdown_event.is_set():
                log().info("已请求关闭，停止钱包处理")
                return
            if time.time() - wallet_start_time > wallet_timeout:
                log().warning(f"钱包处理已达到 {wallet_timeout//60} 分钟的超时时间")
                return
            min_amount = config_data["bridge"]["amount"]["min"]
            max_amount = config_data["bridge"]["amount"]["max"]
            amount = round(random.uniform(min_amount, max_amount), 5)
            log().info(f"桥接尝试 {j+1}/{config_data['bridge']['repeat_count']}")
            
            if config_data["bridge"].get("custom_flow", False) and "bridge_paths" in config_data["bridge"]:
                bridge_paths = config_data["bridge"]["bridge_paths"]
                log().info(f"使用自定义桥接流程，包含 {len(bridge_paths)} 条路径")
                for i, path in enumerate(bridge_paths):
                    from_chain = path["from_chain"]
                    to_chain = path["to_chain"]
                    log().info(f"桥接 {i+1}/{len(bridge_paths)}: {amount} ETH 从 {from_chain} 到 {to_chain}")
                    bridge_timeout = 20 * 60
                    bridge_start_time = time.time()
                    tx_hash = bridge_service.bridge(from_chain=from_chain, to_chain=to_chain, amount=amount)
                    if tx_hash:
                        log().success(f"{from_chain} 到 {to_chain} 的桥接已启动: {tx_hash[:10]}...")
                        if config_data["bridge"].get("wait_for_completion", True):
                            log().info("等待桥接完成...")
                            remaining_timeout = max(10, wallet_timeout - int(time.time() - wallet_start_time))
                            timeout_minutes = min(15, remaining_timeout // 60)
                            bridge_completed = bridge_service.wait_for_completion(
                                tx_hash=tx_hash,
                                timeout_minutes=timeout_minutes,
                                source_chain=from_chain
                            )
                            if not bridge_completed:
                                log().error(f"从 {from_chain} 到 {to_chain} 的桥接失败或超时")
                    else:
                        log().error(f"从 {from_chain} 到 {to_chain} 的桥接交易失败")
                    if i < len(bridge_paths) - 1:
                        delay_time = config_data['delay'].get('between_bridges', 30)
                        log().info(f"等待 {delay_time} 秒后开始下一次桥接...")
                        for _ in range(delay_time):
                            if shutdown_event.is_set():
                                log().info("已请求关闭，停止钱包处理")
                                return
                            if time.time() - wallet_start_time > wallet_timeout:
                                log().warning(f"在延迟期间达到钱包处理超时")
                                return
                            time.sleep(1)
            else:
                from_chain_1 = "base_sepolia"
                to_chain_1 = "optimism_sepolia"
                log().info(f"正在桥接 {amount} ETH 从 {from_chain_1} 到 {to_chain_1}")
                bridge_timeout = 20 * 60
                bridge_start_time = time.time()
                tx_hash_base_to_op = bridge_service.bridge(from_chain=from_chain_1, to_chain=to_chain_1, amount=amount)
                if tx_hash_base_to_op:
                    log().success(f"{from_chain_1} 到 {to_chain_1} 的桥接成功: {tx_hash_base_to_op[:10]}...")
                    if config_data["bridge"].get("wait_for_completion", True):
                        log().info("等待第一次桥接完成...")
                        remaining_timeout = max(10, wallet_timeout - int(time.time() - wallet_start_time))
                        timeout_minutes = min(15, remaining_timeout // 60)
                        bridge_completed = bridge_service.wait_for_completion(
                            tx_hash=tx_hash_base_to_op,
                            timeout_minutes=timeout_minutes,
                            source_chain=from_chain_1
                        )
                        if not bridge_completed:
                            log().error(f"从 {from_chain_1} 到 {to_chain_1} 的桥接失败或超时")
                            continue
                    delay_time = config_data['delay'].get('between_bridges', 30)
                    log().info(f"等待 {delay_time} 秒后进行第二次桥接...")
                    for _ in range(delay_time):
                        if shutdown_event.is_set():
                            log().info("已请求关闭，停止钱包处理")
                            return
                        if time.time() - wallet_start_time > wallet_timeout:
                            log().warning(f"在延迟期间达到钱包处理超时")
                            return
                        time.sleep(1)
                    from_chain_2 = "optimism_sepolia"
                    to_chain_2 = "base_sepolia"
                    second_amount = round(random.uniform(min_amount, max_amount), 5)
                    log().info(f"正在桥接 {second_amount} ETH 从 {from_chain_2} 到 {to_chain_2}")
                    bridge_timeout = 20 * 60
                    bridge_start_time = time.time()
                    tx_hash_op_to_base = bridge_service.bridge(from_chain=from_chain_2, to_chain=to_chain_2, amount=second_amount)
                    if tx_hash_op_to_base:
                        log().success(f"{from_chain_2} 到 {to_chain_2} 的桥接成功: {tx_hash_op_to_base[:10]}...")
                        if config_data["bridge"].get("wait_for_completion", True):
                            log().info("等待第二次桥接完成...")
                            remaining_timeout = max(10, wallet_timeout - int(time.time() - wallet_start_time))
                            timeout_minutes = min(15, remaining_timeout // 60)
                            bridge_completed = bridge_service.wait_for_completion(
                                tx_hash=tx_hash_op_to_base,
                                timeout_minutes=timeout_minutes,
                                source_chain=from_chain_2
                            )
                            if not bridge_completed:
                                log().error(f"从 {from_chain_2} 到 {to_chain_2} 的桥接失败或超时")
                    else:
                        log().error(f"从 {from_chain_2} 到 {to_chain_2} 的桥接交易失败")
                else:
                    log().error(f"从 {from_chain_1} 到 {to_chain_1} 的桥接交易失败")
            if j < config_data["bridge"]["repeat_count"] - 1:
                delay_time = config_data['delay'].get('between_repeats', 60)
                log().info(f"等待 {delay_time} 秒后进行下一次重复操作...")
                for _ in range(delay_time):
                    if shutdown_event.is_set():
                        log().info("已请求关闭，停止钱包处理")
                        return
                    if time.time() - wallet_start_time > wallet_timeout:
                        log().warning(f"在延迟期间达到钱包处理超时")
                        return
                    time.sleep(1)
        log().success(f"钱包 {masked_address} 已成功完成所有 {config_data['bridge']['repeat_count']} 次桥接操作")
    except Exception as e:
        log().error(f"处理钱包时出错: {str(e)}")
        traceback.print_exc()
    finally:
        SessionManager.close_sessions()
        Web3ConnectionManager.close_connections()

def worker_thread():
    """工作线程处理钱包队列。"""
    while not shutdown_event.is_set():
        try:
            try:
                wallet_info = wallet_queue.get(block=False)
            except queue.Empty:
                time.sleep(1)
                continue
            if shutdown_event.is_set():
                wallet_queue.put(wallet_info)
                break
            process_wallet(wallet_info)
            wallet_queue.task_done()
        except Exception as e:
            logger.error(f"工作线程中出错: {str(e)}")
            traceback.print_exc()
            time.sleep(5)
    logger.info("工作线程正在退出")

def run_bridge_task(config, private_keys, proxy_manager):
    """运行桥接任务。"""
    if not private_keys:
        logger.error("未配置私钥！请先配置私钥。")
        return
    total_wallets = len(private_keys)
    logger.info(f"已加载 {total_wallets} 个钱包")
    num_threads = min(config.get('threads', 5), total_wallets)
    threads = []
    logger.info(f"启动 {num_threads} 个工作线程")
    for i in range(num_threads):
        thread = threading.Thread(target=worker_thread, daemon=True)
        thread.start()
        threads.append(thread)
    for i, private_key in enumerate(private_keys):
        proxy = proxy_manager.get_proxy(i)
        wallet_info = {
            "private_key": private_key,
            "index": i,
            "total_wallets": total_wallets,
            "proxy": proxy,
            "config": config
        }
        wallet_queue.put(wallet_info)
    while not wallet_queue.empty() and not shutdown_event.is_set():
        remaining = wallet_queue.unfinished_tasks
        if remaining % num_threads == 0 or remaining < num_threads:
            logger.info(f"剩余待处理钱包: {remaining}/{total_wallets}")
        time.sleep(5)
    if shutdown_event.is_set():
        logger.info("等待工作线程完成当前任务...")
        for thread in threads:
            thread.join(timeout=10)
        logger.info("工作线程已退出")
        logger.info(f"剩余未处理钱包: {wallet_queue.unfinished_tasks}")
    else:
        logger.info("等待所有钱包处理完成...")
        wallet_queue.join()
        logger.info("所有钱包已处理完成！")

def main():
    """程序主入口。"""
    display_banner()
    setup_logger()
    
    # 初始化配置
    try:
        config_manager = ConfigManager()
        config = config_manager.get_config()
    except Exception as e:
        logger.error(f"加载配置失败: {str(e)}")
        sys.exit(1)
    
    private_keys = read_private_keys()
    proxies = []
    use_proxy = config.get('use_proxy', False)
    
    # 如果存在 proxy.txt，尝试加载
    if os.path.exists("proxy.txt"):
        try:
            with open("proxy.txt", "r") as file:
                proxies = [line.strip() for line in file.readlines() if line.strip() and not line.strip().startswith('#')]
            if proxies:
                use_proxy = True
        except Exception as e:
            logger.error(f"加载代理时出错: {str(e)}")
    
    proxy_manager = ProxyManager(use_proxy=use_proxy)
    if proxies:
        proxy_manager.proxies = proxies
        proxy_manager.use_proxy = use_proxy
    
    # 交互式菜单循环
    while True:
        choice = display_menu()
        if choice == "1":
            private_keys = configure_private_keys()
        elif choice == "2":
            proxies, use_proxy = configure_proxies()
            proxy_manager = ProxyManager(use_proxy=use_proxy)
            if proxies:
                proxy_manager.proxies = proxies
                proxy_manager.use_proxy = use_proxy
            config['use_proxy'] = use_proxy
        elif choice == "3":
            view_configuration(config, private_keys, proxies, use_proxy)
        elif choice == "4":
            run_bridge_task(config, private_keys, proxy_manager)
        elif choice == "5":
            logger.info("退出程序。")
            sys.exit(0)
        else:
            print("无效选项！请重新输入。")

if __name__ == "__main__":
    main()
