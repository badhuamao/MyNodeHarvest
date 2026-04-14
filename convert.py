import requests
import yaml
import re
import os
from urllib.parse import urlparse, unquote

# 文件配置
URLS_FILE = "urls.txt"
OUTPUT_FILE = "clash.yaml"

def parse_only_hy2(text):
    """暴力提取并只保留 Hysteria2 协议链接"""
    proxies = []
    # 仅匹配 hy2 或 hysteria2 开头的链接
    links = re.findall(r'(?:hysteria2|hy2)://[^\s"\'|]+', text)
    
    for link in links:
        try:
            parsed = urlparse(link)
            if '@' not in parsed.netloc: continue
            
            auth, server_port = parsed.netloc.split('@')
            server, port = server_port.split(':')
            query = dict(q.split('=') for q in parsed.query.split('&') if '=' in q)
            # 自动解码名字，移除可能导致 YAML 报错的特殊字符
            name = unquote(parsed.fragment) if parsed.fragment else f"Hy2_{server}"
            
            # 构造标准的 Clash Hysteria2 配置
            proxies.append({
                "name": name.strip(),
                "type": "hysteria2",
                "server": server,
                "port": int(port),
                "password": auth,
                "sni": query.get('sni', server),
                "skip-cert-verify": True, # 核心修复：强制跳过证书校验
                "alpn": ["h3"],
                "up": query.get('up', '100'),
                "down": query.get('down', '100')
            })
        except:
            continue
    return proxies

def main():
    all_proxies = []
    seen_nodes = set() # 依然保留去重逻辑

    if not os.path.exists(URLS_FILE):
        return

    # 从 urls.txt 读取待爬取的地址
    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    headers = {'User-Agent': 'ClashforWindows/0.20.39'}

    for url in urls:
        try:
            print(f"正在提取 HY2 节点: {url}")
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200: continue
            
            nodes = parse_only_hy2(resp.text)
            for node in nodes:
                # 去重指纹：服务器地址 + 端口
                fingerprint = f"{node['server']}:{node['port']}"
                if fingerprint not in seen_nodes:
                    all_proxies.append(node)
                    seen_nodes.add(fingerprint)
        except Exception as e:
            print(f"抓取出错: {e}")

    # 构建 Clash 配置文件结构
    clash_config = {
        "proxies": all_proxies,
        "proxy-groups": [
            {
                "name": "🐻 熊家 HY2 专线",
                "type": "url-test",
                "proxies": [p['name'] for p in all_proxies] if all_proxies else ["DIRECT"],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": ["MATCH,🐻 熊家 HY2 专线"]
    }

    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"提取完成！共获得 {len(all_proxies)} 个唯一 HY2 节点。")

if __name__ == "__main__":
    main()
