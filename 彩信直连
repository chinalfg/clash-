tproxy-port: 1536
allow-lan: true
external-controller: 127.0.0.1:9090
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true

find-process-mode: always
keep-alive-interval: 15

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: false
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "Mijia Cloud"

tun:
  enable: false
  stack: mixed
  dns-hijack:
    - "any:53"
  auto-route: true
  auto-detect-interface: true

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/15
  fake-ip-filter:
    - "*"
    - "+.lan"
    - "+.local"
  respect-rules: true
  default-nameserver:
    - "https://1.12.12.12/dns-query"
    - "https://223.5.5.5/dns-query"
  nameserver:
    - "https://dns.cloudflare.com/dns-query"
    - "https://dns.google/dns-query"
  proxy-server-nameserver:
    - "https://1.12.12.12/dns-query"
    - "https://223.5.5.5/dns-query"
  nameserver-policy:
    "rule-set:cn_domain,private":
      - "https://1.12.12.12/dns-query"
      - "https://223.5.5.5/dns-query"
      
proxies:
  - name: "dns-out"
    type: dns 
  
  - name: "彩信直连"
    type: http
    server: 14.215.182.75
    port: 443
    headers:
      X-T5-Auth: 683556433
      Host: 153.3.236.22:443
    dialer-proxy: 局域网

  - name: "局域网"
    type: http
    server: 10.0.0.200
    port: 80

p: &p {type: http, interval: 86400, health-check: {enable: true, url: https://www.gstatic.com/generate_204, interval: 18000, lazy: true}}

proxy-providers:
  SYN:
    <<: *p
    url: "http://127.0.0.1:3000/download/Syn?target=ClashMeta"
    path: "./providers/SYN.yaml"
    override:
      skip-cert-verify: true
      dialer-proxy: 彩信直连
         
  木瓜云:
    <<: *p
    url: "http://127.0.0.1:3000/download/%E6%9C%A8%E7%93%9C?target=Clash"
    path: "./providers/木瓜云.yaml"
    override:
      skip-cert-verify: true
      dialer-proxy: 彩信直连
  


proxy-groups:
  - name: "domestic"
    type: select
    filter: ^(?!.*(ipv6|游戏)).*(CN|联通|移动|电信|广西)
    proxies:
      - "彩信直连"
      - "DIRECT"
      - "PASS"

  - name: "overseas"
    type: select
    filter: ^(?!.*(ipv6)).*(香港|HK|台湾|TW|新加坡|SG|日本|JP|韩国|KR|US|Hong Kong|Japan|Tai wan)
    url: 'http://www.apple.com/library/test/success.html'
    interval: 300
    tolerance: 50
    use:
      - "SYN"
    
      

  - name: "Telegram"
    type: select
    filter: ^(?!.*(ipv6)).*(香港|HK|台湾|TW|新加坡|SG|日本|JP|韩国|KR|US|Hong Kong|Japan|Tai wan)
    url: 'http://www.apple.com/library/test/success.html'
    interval: 300
    tolerance: 50
    use:
      - "SYN"
    
  - name: "UDP Rules"
    type: url-test
    filter: ^(?!.*(ipv6)).*(CN)
    url: 'http://www.apple.com/library/test/success.html'
    interval: 300
    tolerance: 50
    use:
      - "木瓜云"
      
  - name: "Ad blocking"
    type: select
    proxies:
      - "REJECT-DROP"
      - "PASS"
  


rules:
  - DST-PORT,53,dns-out
  - RULE-SET,anti_ad,Ad blocking
  - RULE-SET,private,DIRECT
  - RULE-SET,google_domain,overseas
  - RULE-SET,telegram_ip,Telegram
  - DOMAIN-SUFFIX,clip.makima.online,彩信直连
  - RULE-SET,geolocation-!cn,overseas
  - SUB-RULE,(AND,((RULE-SET,cn_domain))),domestic
  - SUB-RULE,(AND,((RULE-SET,cn_ip))),domestic
  - MATCH,overseas
  - MATCH,REJECT
  
sub-rules:
  domestic:
    - AND,((NETWORK,UDP)),UDP Rules
    - MATCH,domestic
    
rule-anchor:
  domain: &domain {type: http, interval: 86400, behavior: domain, format: yaml}
  ip: &ip {type: http, interval: 86400, behavior: ipcidr, format: yaml}
  
rule-providers:
  anti_ad:
    <<: *domain
   # url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.yaml"
  #  url: "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml"
  
    url: "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.yaml"
  private:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.yaml"
  cn_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml"
  geolocation-!cn:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.yaml"
  google_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.yaml"

  cn_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.yaml"

  telegram_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.yaml"
