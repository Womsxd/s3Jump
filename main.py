from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse
import re
import hmac
import time
import yaml
import asyncio
import hashlib
import logging
import threading
import urllib.parse
from typing import Dict
from rule_engine import compile_rule_expr, select_node

RANGE_RE = re.compile(r"bytes=(\d+)-(\d*)")


app = FastAPI()

config_lock = threading.Lock()
config_path = "config.yaml"

# 配置信息实体类
class Config:
    def __init__(self):
        self.original_access_key = ""
        self.original_secret_key = ""
        self.target_nodes = []  # 多目标节点配置列表，元素为规则集字典，包含规则集信息和节点权重
        self.rules = []

config = Config()

# 新增节点当前上传带宽状态字典，线程安全
now_bandwidth_lock = threading.Lock()
now_bandwidths = {}  # key: node_name, value: 当前上传带宽，单位Mbps

logging.basicConfig(level=logging.INFO)



def sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key: str, date_stamp: str, region: str) -> bytes:
    """Minio专用签名密钥生成"""
    k_date = sign(f"AWS4{key}".encode(), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, "s3")
    return sign(k_service, "aws4_request")


def normalize_path(path: str) -> str:
    """Minio路径标准化处理"""
    # 保留原始路径中的斜杠结构
    decoded = urllib.parse.unquote(path)
    parts = decoded.split("/")
    encoded_parts = [urllib.parse.quote(p, safe="~") for p in parts]
    return "/".join(encoded_parts)


def create_canonical_request(
        method: str,
        path: str,
        query: Dict[str, str],
        headers: Dict[str, str],
        signed_headers: str,
        payload_hash: str
) -> str:
    """符合Minio规范的请求生成"""
    # 1. 路径处理
    normalized_path = normalize_path(path)

    # 2. 查询参数处理
    filtered = {k: v for k, v in query.items() if k != "X-Amz-Signature"}
    sorted_query = sorted(filtered.items(), key=lambda x: x[0])
    encoded_query = "&".join(
        f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
        for k, v in sorted_query
    )

    # 3. 请求头处理
    header_map = {k.lower(): v.strip() for k, v in headers.items()}
    sorted_headers = sorted(header_map.items(), key=lambda x: x[0])
    canonical_headers = "\n".join(f"{k}:{v}" for k, v in sorted_headers) + "\n"

    return "\n".join([
        method,
        normalized_path,
        encoded_query,
        canonical_headers,
        signed_headers,
        payload_hash
    ])


async def verify_minio_signature(request: Request) -> bool:
    """Minio签名验证"""
    try:
        query = dict(request.query_params)

        # 解码凭证
        credential = urllib.parse.unquote(query["X-Amz-Credential"])
        parts = credential.split("/")
        date_stamp = parts[1]
        region = parts[2]

        # 构造签名要素
        method = request.method
        path = request.url.path
        signed_headers = query["X-Amz-SignedHeaders"]
        headers = {h: request.headers.get(h, "") for h in signed_headers.split(";")}

        # 生成规范请求
        canonical_request = create_canonical_request(
            method=method,
            path=path,
            query=query,
            headers=headers,
            signed_headers=signed_headers,
            payload_hash="UNSIGNED-PAYLOAD"  # Minio预签名请求固定值
        )

        # 生成待签字符串
        credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            query["X-Amz-Date"],
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest()
        ])

        # 计算签名
        with config_lock:
            signing_key = get_signature_key(config.original_secret_key, date_stamp, region)
        new_signature = hmac.new(
            signing_key,
            string_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(new_signature, query["X-Amz-Signature"])
    except Exception as e:
        print(f"\n[Verification Error] {str(e)}")
        return False




def resign_request(request: Request) -> str:
    """重新签名请求"""
    query = dict(request.query_params)
    path = request.url.path

    # 从请求头获取Range字段，解析文件大小范围
    range_header = request.headers.get("Range", "")
    file_size = None
    if range_header:
        m = RANGE_RE.match(range_header)
        if m:
            start = int(m.group(1))
            end = m.group(2)
            if end:
                end = int(end)
                file_size = end - start + 1
            else:
                file_size = None  # 未指定结束，忽略大小限制

    # 传入带宽信息到规则上下文
    with now_bandwidth_lock:
        # 取当前请求path对应节点的带宽，默认0
        node_bandwidth = now_bandwidths.get(selected_node.get("name", ""), 0)
    
    # 构造上下文字典，方便扩展更多变量
    context = {
        "size": file_size,
        "method": request.method,
        "path": request.url.path,
        "headers": dict(request.headers),
        "query_params": dict(request.query_params),
        "node_bandwidth": node_bandwidth,
    }

    selected_node = select_node(context, config.rules, config.target_nodes)

    if not selected_node:
        logging.error("未能选择到目标节点")
        return ""

    access_key = selected_node.get("access_key","")
    secret_key = selected_node.get("secret_key","")
    region = selected_node.get("region","")
    endpoint = selected_node.get("endpoint","")

    # ak sk region为空则直接返回未签名的链接
    if not access_key or not secret_key or not region:
        return f"https://{endpoint}{path}"

    # 更新凭证信息
    date_stamp = query["X-Amz-Date"][:8]
    new_credential = f"{access_key}/{date_stamp}/{region}/s3/aws4_request"

    # 构造新参数
    new_query = {k: v for k, v in query.items() if k != "X-Amz-Signature"}
    new_query["X-Amz-Credential"] = new_credential

    # 处理请求头（替换host）
    signed_headers = query["X-Amz-SignedHeaders"]
    headers = {
        h: selected_node["endpoint"] if h.lower() == "host" else request.headers.get(h, "")
        for h in signed_headers.split(";")
    }

    # 生成新规范请求
    canonical_request = create_canonical_request(
        method=request.method,
        path=path,
        query=new_query,
        headers=headers,
        signed_headers=signed_headers,
        payload_hash="UNSIGNED-PAYLOAD"
    )

    # 生成新签名
    credential_scope = f"{date_stamp}/{selected_node['region']}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        query["X-Amz-Date"],
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest()
    ])

    signing_key = get_signature_key(secret_key, date_stamp, region)
    new_signature = hmac.new(
        signing_key,
        string_to_sign.encode(),
        hashlib.sha256
    ).hexdigest()

    # 构造最终URL
    new_query["X-Amz-Signature"] = new_signature
    encoded_query = urllib.parse.urlencode(new_query, doseq=True)
    return f"https://{endpoint}{path}?{encoded_query}"


def load_config():
    global config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        original_access_key = cfg.get("original_access_key", "")
        original_secret_key = cfg.get("original_secret_key", "")

        raw_nodes = cfg.get("target_nodes", {})
        raw_rules = cfg.get("rules", {})
        rules_use = cfg.get("rules_use", None)  # 新增rules_use字段读取

        enabled_nodes = {name: info for name, info in raw_nodes.items() if info.get("enabled", True) and info.get("endpoint")}

        # 初始化当前上传带宽为0
        with now_bandwidth_lock:
            for node_name in enabled_nodes.keys():
                now_bandwidths[node_name] = 0

        compiled_rule_sets = []
        for rule_name, rule_entry in raw_rules.items():
            # 如果rules_use存在且rule_name不在其中，则跳过该规则
            if rules_use is not None and rule_name not in rules_use:
                continue
    
            # 允许rule_name为空字符串，表示匹配全部请求
            if rule_name is None:
                rule_name = ""
    
            mode = rule_entry.get("mode", "and") or "and"
            rules_exprs = rule_entry.get("rules", [])
            use_list = rule_entry.get("use", [])
            try:
                allowed_names = set()
                for expr in rules_exprs:
                    parts = expr.strip().split()
                    if parts:
                        allowed_names.add(parts[0])
                compiled_rule_funcs = [compile_rule_expr(expr, allowed_names) for expr in rules_exprs]
            except Exception as e:
                logging.warning(f"规则表达式预编译失败，规则集 {rule_name}，错误: {e}")
                compiled_rule_funcs = []
    
            node_weights = {}
            for item in use_list:
                parts = item.split()
                if len(parts) == 2:
                    node, weight_str = parts
                    try:
                        weight = float(weight_str)
                        if node in enabled_nodes:
                            node_weights[node] = weight
                        else:
                            logging.warning(f"use中节点 {node} 不存在或未启用，跳过")
                    except Exception as e:
                        logging.warning(f"use中权重解析失败: {item}，错误: {e}")
                else:
                    logging.warning(f"use格式错误: {item}")
    
            compiled_rule_sets.append({
                "rule_name": rule_name,
                "mode": mode,
                "rules": compiled_rule_funcs,
                "node_weights": node_weights
            })
        with config_lock:
            config.original_access_key = original_access_key
            config.original_secret_key = original_secret_key
            config.target_nodes = enabled_nodes
            config.rules = compiled_rule_sets

            # 读取每个节点的node_secret，默认为空字符串
            for node_name, node_info in enabled_nodes.items():
                node_info["node_secret"] = node_info.get("node_secret", "")

            logging.info(f"加载配置文件成功，启用目标节点数: {len(config.target_nodes)}")
    except Exception as e:
        logging.error(f"加载配置文件失败: {e}")

# load_config()

@app.get("/reload-config")
async def reload_config():
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, load_config)
        return {"message": "配置文件重载成功"}
    except Exception as e:
        return {"error": f"配置文件重载失败: {e}"}

# 新增接口，节点上报当前上传带宽，单位Mbps
@app.post("/report-bandwidth")
async def report_bandwidth(request: Request, data: dict):
    # 动态鉴权，客户端请求头中带有 X-Auth-Token，格式: "{timestamp},{hmac}"
    auth_header = request.headers.get("X-Auth-Token")
    if not auth_header:
        return {"error": "缺少鉴权头 X-Auth-Token"}, status.HTTP_401_UNAUTHORIZED

    try:
        node_name = data.get("node_name")
        now_bandwidth = data.get("now_bandwidth")
        if not node_name or now_bandwidth is None:
            return {"error": "缺少node_name或now_bandwidth字段"}, status.HTTP_400_BAD_REQUEST

        now_bandwidth = float(now_bandwidth)
    except ValueError:
        return {"error": "now_bandwidth必须是数字"}, status.HTTP_400_BAD_REQUEST

    # 解析鉴权头
    try:
        timestamp_str, client_hmac = auth_header.split(",", 1)
        timestamp = int(timestamp_str)
    except Exception:
        return {"error": "鉴权头格式错误"}, status.HTTP_400_BAD_REQUEST

    current_ts = int(time.time())
    # 时间戳有效期10s，因为数据上报很频繁
    if abs(current_ts - timestamp) > 10:
        return {"error": "鉴权失败，时间戳过期"}, status.HTTP_401_UNAUTHORIZED

    # 计算服务端hmac
    node_info = config.target_nodes.get(node_name)
    if not node_info:
        return {"error": f"节点 {node_name} 不存在或未启用"}, status.HTTP_404_NOT_FOUND
    node_secret = node_info.get("node_secret", "")

    message = f"{node_name}|{now_bandwidth}|{timestamp_str}"
    server_hmac = hmac.new(node_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(server_hmac, client_hmac):
        return {"error": "鉴权失败，HMAC不匹配"}, status.HTTP_401_UNAUTHORIZED

    if node_name in now_bandwidths:
        with now_bandwidth_lock:
            now_bandwidths[node_name] = now_bandwidth
    else:
        return {"error": f"节点 {node_name} 不存在或未启用"}, status.HTTP_404_NOT_FOUND

    return {"message": f"节点 {node_name} 当前上传带宽更新成功", "now_bandwidth": now_bandwidth}

@app.api_route("/{path:path}", methods=["GET", "HEAD"])
async def gateway_handler(request: Request, path: str):
    required_params = ["X-Amz-Algorithm", "X-Amz-Credential",
                       "X-Amz-Signature", "X-Amz-Date", "X-Amz-SignedHeaders"]
    if any(p not in request.query_params for p in required_params):
        return {"error": "Missing signature parameters"}, status.HTTP_400_BAD_REQUEST

    try:
        credential = urllib.parse.unquote(request.query_params["X-Amz-Credential"]).split("/")[0]
        with config_lock:
            if credential != config.original_access_key:
                return {"error": "Invalid access key"}, status.HTTP_403_FORBIDDEN
    except Exception:
        return {"error": "Credential parse error"}, status.HTTP_400_BAD_REQUEST

    if not await verify_minio_signature(request):
        return {"error": "Signature mismatch"}, status.HTTP_403_FORBIDDEN

    redirect_url = resign_request(request)
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="启动参数")
    parser.add_argument("-p", "--port", type=int, default=9100, help="监听端口，默认9100")
    parser.add_argument("-c", "--config", type=str, default="config.yaml", help="配置文件路径，默认config.yaml")
    args = parser.parse_args()

    config_path = args.config
    load_config()
    # 移除原有的load_config调用，改为启动时根据参数调用

    uvicorn.run(app, host="0.0.0.0", port=args.port)
