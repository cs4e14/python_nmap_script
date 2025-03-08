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

            elif flags & 0x12 and (dst_ip, src_ip, dst_port) in syn_packets:  # SYN-ACK -> פורט פתוח
                open_ports[dst_port] = 'Open'

            elif flags & 0x04 and (dst_ip, src_ip, dst_port) in syn_packets:  # RST -> פורט סגור
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

            if flags == 0x01:  # FIN Scan (-sF)
                fin_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

            elif flags == 0x00:  # NULL Scan (-sN)
                null_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

            elif flags == 0x29:  # Xmas Scan (-sX)
                xmas_scans.add((src_ip, dst_ip, dst_port))
                attacker_ips.add(src_ip)

            elif flags == 0x10 and not (flags & 0x02):  # ACK Scan (-sA)
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
