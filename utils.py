import time
import sys
from loguru import logger

# 显示横幅
def display_banner():
    """显示程序启动时的ASCII艺术横幅。"""
    print("\n")
    print("""
████████╗██████╗ ██████╗ ███╗   ██╗
╚══██╔══╝╚════██╗██╔══██╗████╗  ██║
   ██║    █████╔╝██████╔╝██╔██╗ ██║
   ██║   ██╔═══╝ ██╔══██╗██║╚██╗██║
   ██║   ███████╗██║  ██║██║ ╚████║
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
     桥接测试网自动化
    """)
    print("\n")
    print("T3RN桥接机器人 - 测试网自动化")
    print("支持的链: Base Sepolia, Optimism Sepolia")
    print("=" * 50)
    print("\n")

# 处理动画
def display_processing_animation(message="处理中"):
    """创建处理动画的上下文管理器。"""
    class ProcessingAnimation:
        def __init__(self, message):
            self.message = message
            self.is_running = False
        
        def __enter__(self):
            logger.info(f"{self.message}...")
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:
                logger.info(f"{self.message}已完成")
            else:
                logger.error(f"{self.message}失败: {str(exc_val)}")
    
    return ProcessingAnimation(message)
