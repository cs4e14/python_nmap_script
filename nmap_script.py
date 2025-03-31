import pyshark

1. סריקות בסיסיות
- -sP (Ping scan)

סריקה זו משמשת לאיתור האם מכשירים פעילים ברשת. זוהי סריקה פשוטה שמבצעת רק שליחת בקשות "Ping" לכל כתובת IP ברשת וממתינה לתגובה.

מתי נשתמש: בשלב ראשוני, כאשר נרצה לדעת אילו מכשירים פעילים על הרשת.
למה נרצה: זו סריקה מהירה וזולה שמאפשרת לנו לבדוק את פעולתה של הרשת.
- -sT (TCP connect scan)

סריקה זו מבצעת התחברות מלאה ליציאות ה-TCP על המכשירים ברשת, ומנסה לחבר לכל יציאה כדי לבדוק אם היא פתוחה.

מתי נשתמש: כשלא יש לנו גישה לשימוש ב-syn scan (למשל בסביבת עבודה עם הרשאות מוגבלות) או כשאנחנו רוצים סריקה מלאה שמבוססת על התחברות רגילה.
למה נרצה: נותן תמונה מדויקת של יציאות פתוחות, אך יש לה חסרון של דרישת יותר זמן.
2. סריקות חזקות או סריקות סינכרוניות
- -sS (SYN scan)

סריקה זו מבוססת על שליחת חבילות SYN (שאילתות חיבור) ליציאות ה-TCP כדי לבדוק אם הן פתוחות. היא אינה מבצעת חיבור מלא אלא חצי-חיבור (Half-open), שהיא טכניקת סריקה חמקנית.

מתי נשתמש: כשנרצה לגלות יציאות פתוחות מהר ובלי להתגלות על ידי המערכת.
למה נרצה: הסריקה חמקנית יחסית, כי היא לא משאירה חיבור מלא, והיא מהירה יותר מ-sTCP connect.
- -sF (FIN scan)

סריקה זו שולחת חבילות FIN (סיום) במקום SYN, שהיא לא אמורה לעורר תגובה. כל תגובה שהיא (כגון RST) עשויה להעיד על יציאה פתוחה.

מתי נשתמש: כשנרצה להימנע ממעקב של מערכות IPS/IDS או כשנרצה לבצע סריקה חמקנית יותר.
למה נרצה: זוהי סריקה דיסקרטית מאוד שנמצאת מתחת לרדאר של רוב מערכות הגילוי.
3. סריקות סיסמאות והשירותים הפועלים
- -sV (Service version detection)

סריקה זו בודקת את הגירסאות של השירותים הפועלים על היציאות הפתוחות. Nmap שולח שאלות חכמות לשירותים (כגון HTTP, FTP, SSH וכו') כדי לזהות את הגרסה שלהם.

מתי נשתמש: כשנרצה לדעת אילו שירותים פועלים על המחשב ולקבל מידע על גרסאותיהם.
למה נרצה: זה עוזר לזהות פרצות אבטחה ידועות הקשורות לגרסאות ישנות של שירותים מסוימים.
- -O (OS detection)

סריקה זו מנסה לזהות את מערכת ההפעלה של המחשב המרוחק על ידי ניתוח חבילות ה-TCP וה-UDP שכתוצאה מהן.

מתי נשתמש: כשנרצה לדעת איזה מערכת הפעלה רצה על המחשב המרוחק.
למה נרצה: ידע על מערכת הפעלה מסייע בתכנון אסטרטגיות פריצה או אבטחה.
4. סריקות חמקניות ובלתי נראות
- -sA (ACK scan)

סריקה זו שולחת חבילות ACK וממתינה לתגובה (או לא). זה משמש כדי לגלות חומות אש (Firewalls) על הרשת ולא בהכרח לבדוק אילו יציאות פתוחות.

מתי נשתמש: כשנרצה לזהות אם יש חומת אש בדרך או לסרוק את הגדרות חומת האש.
למה נרצה: הסריקה אינה מנסה להתחבר לשירותים עצמם, אלא רק בודקת חומות אש.
- -sU (UDP scan)

סריקה זו פועלת עם פרוטוקול UDP ולא TCP. היא משמשת לאיתור יציאות פתוחות בשירותים שלא פועלים עם TCP, כמו DNS, SNMP, ועוד.

מתי נשתמש: כאשר יש צורך לבדוק יציאות UDP.
למה נרצה: הרבה פעמים שירותים חשובים מבוססים על UDP, וזו הדרך היחידה לסרוק אותם.
5. סריקות דינמיות ומתוחכמות
- -T4 או -T5 (Timing templates)

סריקות אלו נועדו לשנות את זמן הסריקה. -T4 מתכננת סריקה מהר יותר, ו--T5 מהר עוד יותר, אך עשויות להפסיק לפעול תחת הגדרות רשת מסוימות.

מתי נשתמש: אם אנחנו צריכים לסיים סריקה באופן מהיר ויעיל.
למה נרצה: זה מאפשר לסרוק רשתות בצורה הרבה יותר מהירה, אך יש סיכון לגילוי.
סריקות חשאיות:
כאשר נרצה לבצע סריקה חשאית, נבחר בשיטות שמפחיתות את סיכון הגילוי של פעולתה:

-sS (SYN scan): מאפשרת ביצוע סריקה מבלי להשאיר חיבור מלא.
-sF (FIN scan): מייצרת סריקות שמעוררות פחות חשד.
-sA (ACK scan): יכולה להיות שימושית בחומות אש.
-sN (Null scan): שולחת חבילות ריקות, שיכולות לעזור להימנע מגילוי על ידי מערכות גילוי.




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
