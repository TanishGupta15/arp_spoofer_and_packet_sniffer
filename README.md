# ARP Spoofer and Packet Sniffer

This project contains 2 files:
  
  1. ARP Spoofer
  
      Helps you become the Man in the Middle! Takes as input a source IP and target IP. Spoods target IP into believing that source IP is located at your MAC address and spoofs source IP into believing that target IP is located at your MAC address too!
      
      Usage: Run the script in your terminal by using "python arp_spoofer.py --help" to get different arguments that can be used.
        
      Command: python3 arp_spoofer.py --source source_IP --target target_IP
      
          (Make sure to enclose the target IP and the source IP in double quotes i.e. enter these as strings.)
      
  2. Packet Sniffer
    
      Helps you sniff all the packets exchanged over an interface specified. I have filtered the data to only read URLs visited and UserNames and Passwords filled ;)
      
      Usage:  Run the script in your terminal by using "python mac_changer.py --help" to get different arguments that can be used.
      
      Command: python3 packet_sniffer.py --interface your_interface
       
   
Python Modules used:
   
    1. Subprocess - To execute terminal commands from python script
    
    2. optparse - To read command-line arguments
    
    3. scapy - To scan the networks and get information about them
    
    4. time - Used time.sleep(2) to spoof IPs continously.
    
 
Some points to note:

    1. Make sure to run both files in parallel terminals. While the ARP spoofer is running, run the Packet Sniffer to Sniff the packets.
    
    2. Before sniffing packets, make sure to run the following command in terminal.
    
        Command: echo 1 > /proc/sys/net/ipv4/ip_forward
        
       This command allows Host machine to forward all the packets without dropping any.
       
    3. I have tested the code with Windows 10 on virtual machine as a target machine and router as the source IP.
    
    4. I made a few changes in the dns.py of scapy module. As mentioned in the link: https://github.com/secdev/scapy/issues/1895, there was a small bug with scapy version 2.4.2 which had to be corrected.
