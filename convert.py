import requests
import yaml
import re
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, unquote

# 文件配置
URLS_FILE = "urls.txt"
OUTPUT_FILE = "clash.yaml"
MAX_WORKERS = 50  # 线程数，3000个节点建议设为50-100，太大会被系统限制
CHECK_TIMEOUT = 2  # 连通性测试超时时间（秒）

def parse_only_hy2(text):
    """暴力提取并只保留 Hysteria2 协议链接"""
    proxies = []
    links = re.findall(r'(?:hysteria2|hy2)://[^\s"\'|]+', text)
    
    for link in links:
        try:
            parsed = urlparse(link)
            if '@' not in parsed.netloc: continue
            
            auth, server_port = parsed.netloc.split('@')
            server, port = server_port.split(':')
            query = dict(q.split('=') for q in parsed.query.split('&') if '=' in q)
            name = unquote(parsed.fragment) if parsed.fragment else f"Hy2_{server}"
            
            proxies.append({
                "name": name.strip(),
                "type": "hysteria2",
                "server": server,
                "port": int(port),
                "password": auth,
                "sni": query.get('sni', server),
                "skip-cert-verify": True,
                "alpn": ["h3"],
                "up": query.get('up', '100'),
                "down": query.get('down', '100')
            })
        except:
            continue
    return proxies

def check_port(node):
    """简单的 TCP 连通性检测"""
    try:
        # 注意：HY2 虽然是 UDP，但大部分服务器底层端口 TCP 也是开放的，
        # 或者通过这种方式能过滤掉大部分死 IP。
        with socket.create_connection((node['server'], node['port']), timeout=CHECK_TIMEOUT):
            return node
    except:
        return None

def main():
    all_proxies = []
    seen_nodes = set()

    if not os.path.exists(URLS_FILE):
        print(f"找不到 {URLS_FILE}")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    headers = {'User-Agent': 'ClashforWindows/0.20.39'}

    # 1. 抓取阶段
    raw_nodes = []
    for url in urls:
        try:
            print(f"正在下载源: {url}")
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200: continue
            
            nodes = parse_only_hy2(resp.text)
            for node in nodes:
                fingerprint = f"{node['server']}:{node['port']}"
                if fingerprint not in seen_nodes:
                    raw_nodes.append(node)
                    seen_nodes.add(fingerprint)
        except Exception as e:
            print(f"抓取 {url} 出错: {e}")

    print(f"抓取完成，共发现 {len(raw_nodes)} 个节点。开始多线程检测连通性...")

    # 2. 筛选阶段 (多线程)
    valid_proxies = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交检测任务
        results = executor.map(check_port, raw_nodes)
        for res in results:
            if res:
                valid_proxies.append(res)

    # 3. 写入文件
    clash_config = {
        "proxies": valid_proxies,
        "proxy-groups": [
            {
                "name": "🐻 熊家 HY2 专线",
                "type": "url-test",
                "proxies": [p['name'] for p in valid_proxies] if valid_proxies else ["DIRECT"],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": ["MATCH,🐻 熊家 HY2 专线"]
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    print(f"--- 报告 ---")
    print(f"原始发现: {len(raw_nodes)}")
    print(f"检测有效: {len(valid_proxies)}")
    print(f"剔除死点: {len(raw_nodes) - len(valid_proxies)}")
    print(f"结果已保存至 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
