import logging
import time
from urllib.parse import urlsplit

from colorama import Fore, Style
from fastapi import Request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("custom.access")
logger.propagate = False  # 不传递到 root logger
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


def extract_host(url: str) -> str:
    try:
        return urlsplit(url).netloc
    except Exception:
        return ""


async def custom_logging_middleware(request: Request, call_next):
    start_time = time.time()

    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000

    client_host = request.client.host
    method = request.method
    path = request.url.path
    status_code = response.status_code

    if 200 <= status_code < 300:
        status_color = Fore.GREEN
    elif 300 <= status_code < 400:
        status_color = Fore.YELLOW
    else:
        status_color = Fore.RED

    if method in ("GET", "HEAD"):
        method_color = Fore.CYAN
    else:
        method_color = Fore.BLUE

    # uvicorn 样式的 INFO 前缀（浅绿色）
    info_prefix = f"{Fore.LIGHTGREEN_EX}INFO{Style.RESET_ALL}:     "

    if getattr(request.scope.get("endpoint"), "__name__", "") == "gateway_handler":
        # 如果是 gateway_handler，取 Location 头作为目标域名
        target = response.headers.get("location", "-")
        logger.info(f"{info_prefix}{client_host} - "
                    f"\"{method_color}{method}{Style.RESET_ALL} {path} HTTP/1.1\"  "
                    f"{status_color}{status_code}{Style.RESET_ALL} {extract_host(target)}")
    else:
        # 普通路由的格式
        logger.info(f"{info_prefix}{client_host} - "
                    f"\"{method_color}{method}{Style.RESET_ALL} {path} HTTP/1.1\"  "
                    f"{status_color}{status_code}{Style.RESET_ALL} {process_time:.2f}ms")

    return response
