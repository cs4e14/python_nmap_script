import pyshark

#    sS
def detect_syn_scan(packets):
    syn_packets = {}
    open_ports = {}
    closed_ports = {}
    attacker_ips = set()

    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)

            if flags & 0x02 and not flags & 0x10:  # SYN ללא ACK
                syn_packets[(src_ip, dst_ip, dst_port)] = True
                attacker_ips.add(src_ip)

            elif flags & 0x12 and (dst_ip, src_ip, dst_port) in syn_packets:  
                open_ports[dst_port] = 'Open'

            elif flags & 0x04 and (dst_ip, src_ip, dst_port) in syn_packets: 
                closed_ports[dst_port] = 'Closed'

    return open_ports, closed_ports, attacker_ips


#tcp scans
def detect_tcp_scans(packets):
    fin_scans, null_scans, xmas_scans, ack_scans = set(), set(), set(), set()
    attacker_ips = set()

    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)

            if flags == 0x01:  # (-sF)
                fin_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

            elif flags == 0x00:  # (-sN)
                null_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

            elif flags == 0x29:  #  (-sX)
                xmas_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

            elif flags == 0x10 and not (flags & 0x02):  #  (-sA)
                ack_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

    return fin_scans, null_scans, xmas_scans, ack_scans, attacker_ips


# sV
def detect_service_version_scan(packets):
    sv_scan_candidates = {}
    attacker_ips = set()

    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)

            if flags & 0x10 and flags & 0x08:
                sv_scan_candidates[(src_ip, dst_ip, dst_port)] = 'Service Version Scan'
                attacker_ips.add(src_ip)

    return sv_scan_candidates, attacker_ips

#udp
def detect_udp_scan(packets):
    udp_scans = set()
    attacker_ips = set()

    for packet in packets:
        if 'IP' in packet and 'UDP' in packet:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dst_port = int(packet.udp.dstport)

            udp_scans.add((src_ip, dst_ip, dst_port))
            attacker_ips.add(src_ip)

        elif 'ICMP' in packet and int(packet.icmp.type) == 3 and int(packet.icmp.code) == 3:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            udp_scans.discard((dst_ip, src_ip, None))

    return udp_scans, attacker_ips
def detect_zombie_scan(packets):
    zombie_scans = {}
    attacker_ips = set()
    target_ips = set()

    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)

            # אם יש SYN עם IP לא נגיש (לא נמצא בתוקפים), זה יכול להיות Zombie Scan
            if flags & 0x02 and dst_ip not in target_ips and dst_ip != src_ip:
                zombie_scans[(src_ip, dst_ip, dst_port)] = "Potential Zombie Scan"
                attacker_ips.add(src_ip)  # ה-IP של התוקף

    return zombie_scans

#  (PH)
def detect_port_scan(packets):
    ph_scans = {}
    src_ips_ports = defaultdict(set)  # 

    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)

            if flags & 0x02 and dst_ip != src_ip:  
                src_ips_ports[src_ip].add(dst_port)

  
    for src_ip, ports in src_ips_ports.items():
        if len(ports) > 10:  # 
            ph_scans[src_ip] = "Port Scan (PH)"

    return ph_scans

def extract_ntlm_hash(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="ntlmssp")
    ntlm_hashes = []

    for packet in cap:
        try:
            if 'NTLMSSP' in packet:
                if hasattr(packet.ntlmssp, 'lm_hash') and hasattr(packet.ntlmssp, 'ntlm_hash'):
                    lm_hash = packet.ntlmssp.lm_hash
                    ntlm_hash = packet.ntlmssp.ntlm_hash
                    if lm_hash != "None" and ntlm_hash != "None":
                        print(f"LM Hash: {lm_hash}")
                        print(f"NTLM Hash: {ntlm_hash}")
                        ntlm_hashes.append(ntlm_hash)
        except AttributeError:
            continue

    return ntlm_hashes

def crack_ntlm_hash(ntlm_hashes, wordlist_path):
    for ntlm_hash in ntlm_hashes:
      
        with open("hashes.txt", "w") as hash_file:
            hash_file.write(ntlm_hash + "\n")
        
      
        command = [
            "hashcat", 
            "-m", "1000",  
            "-a", "0",     
            "hashes.txt",  
            wordlist_path  
        ]
        
        
        subprocess.run(command)
