import requests
import yaml
import re
import os
from urllib.parse import urlparse, unquote

# 文件配置
URLS_FILE = "urls.txt"
OUTPUT_FILE = "clash.yaml"

def parse_to_proxies(text):
    """暴力提取所有支持的协议链接"""
    proxies = []
    # 正则表达式：专门抓取各种协议开头的明文链接
    links = re.findall(r'(?:hysteria2|hy2|vless|vmess|ss|trojan)://[^\s"\'|]+', text)
    
    for link in links:
        try:
            parsed = urlparse(link)
            if '@' not in parsed.netloc: continue
            
            auth, server_port = parsed.netloc.split('@')
            server, port = server_port.split(':')
            query = dict(q.split('=') for q in parsed.query.split('&') if '=' in q)
            # 自动解码名字里的表情和中文
            name = unquote(parsed.fragment) if parsed.fragment else f"{parsed.scheme}_{server}"
            
            # Hysteria2 专门处理
            if parsed.scheme in ['hysteria2', 'hy2']:
                proxies.append({
                    "name": name.strip(),
                    "type": "hysteria2",
                    "server": server,
                    "port": int(port),
                    "password": auth,
                    "sni": query.get('sni', server),
                    "skip-cert-verify": True, # 强制跳过证书校验，解决不可用问题
                    "alpn": ["h3"]
                })
            # VLESS 处理
            elif parsed.scheme == 'vless':
                proxies.append({
                    "name": name.strip(),
                    "type": "vless",
                    "server": server,
                    "port": int(port),
                    "uuid": auth,
                    "tls": True,
                    "skip-cert-verify": True,
                    "servername": query.get('sni', server),
                    "network": query.get('type', 'tcp')
                })
        except:
            continue
    return proxies

def main():
    all_proxies = []
    seen_nodes = set() # 去重器

    if not os.path.exists(URLS_FILE):
        print("错误：未找到 urls.txt")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    headers = {'User-Agent': 'ClashforWindows/0.20.39'}

    for url in urls:
        try:
            print(f"正在清洗: {url}")
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code != 200: continue
            
            nodes = parse_to_proxies(resp.text)
            for node in nodes:
                # 唯一性标识：服务器+端口+密码
                # 这样即使名字改了，只要节点是一样的，就不会重复
                fingerprint = f"{node['server']}:{node['port']}"
                if fingerprint not in seen_nodes:
                    all_proxies.append(node)
                    seen_nodes.add(fingerprint)
        except Exception as e:
            print(f"处理失败: {e}")

    # 构建 Clash 结构
    clash_config = {
        "proxies": all_proxies,
        "proxy-groups": [
            {
                "name": "🐻 熊家自动选择",
                "type": "url-test",
                "proxies": [p['name'] for p in all_proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": ["MATCH,🐻 熊家自动选择"]
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    print(f"清洗完成！共获得 {len(all_proxies)} 个唯一节点。")

if __name__ == "__main__":
    main()
