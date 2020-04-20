from scapy.all import *
from itertools import cycle


class ClientList:

    def __init__(self):
        pass

    @staticmethod
    def send_arp_request(ip):
        arp_request_packet = ARP(pdst=ip)
        broadcast_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast_ether/arp_request_packet
        answered_list = srp(arp_packet, timeout=2, verbose=False)[0]
        return answered_list

    def list_ips(self, ip):
        answered_list = self.send_arp_request(ip)
        ip_list = []
        for element in answered_list:
            ip_list.append(element[1].psrc)
        return ip_list

