import socket
import time
import threading
import queue
import subprocess
import ipaddress
import sys
from scapy.all import *
from termcolor import colored
from datetime import datetime
import nmap

socket.setdefaulttimeout(0.25)
print_lock = threading.Lock()

# Scan port
def scan_port(ip_address, port, open_ports):
    """
    This function scans a given IP address and port to check if the port is open.
    If the port is open, it appends the port number to the open_ports list.

    :param ip_address: str
        The IP address to scan.
    :param port: int
        The port number to scan.
    :param open_ports: list
        A list to store the open ports.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)            # create a socket object
    sock.settimeout(5)                                                  # set a timeout of 5 seconds
    result = sock.connect_ex((ip_address, port))                        # attempt to connect to the IP address and port
    if result == 0:                                                     # if the result is 0, the port is open
        open_ports.append(port)                                         # append the port number to the open_ports list
    sock.close()                                                        # close the socket

# Threader
def threader(q, ip):
    """
    This function continuously gets a worker from the queue and calls the scan_port function with the worker and IP address as arguments.
    After the scan_port function is called, the task is marked as done.

    :param q: Queue
        The queue containing the workers.
    :param ip: str
        The IP address to scan.
    """
    while True:
        worker = q.get()                                                # get a worker from the queue
        scan_port(worker, ip)                                           # call the scan_port function with the worker and IP address as arguments
        q.task_done()                                                   # mark the task as done

# Scan host 
def scan_host(ip, ports):
    """
    This function scans a given IP address and a list of ports using multithreading.
    It creates a queue and adds all the ports to the queue.
    Then it creates 100 threads and starts them.
    Each thread calls the threader function with the queue and IP address as arguments.
    After all the threads are done, the function prints the total time taken to scan the IP address.

    :param ip: str
        The IP address to scan.
    :param ports: list
        A list of port numbers to scan.
    """
    print(f"[+] Scanning {ip}")
    startTime = time.time()                                                     # record the start time
    q = queue.Queue()                                                           # create a queue
    for port in ports:
        q.put(port)                                                             # add all the ports to the queue
    for _ in range(100):
        t = threading.Thread(target=threader, args=(q, ip))                     # create a thread and set its target to the threader function
        t.daemon = True                                                         # set the thread as a daemon thread
        t.start()                                                               # start the thread
    q.join()                                                                    # wait for all the threads to finish
    print(f"[+] Finished scanning {ip} in {time.time() - startTime} seconds")   # print the total time taken to scan the IP address


#
#
# Scan host met ping
def host_scan_ping(ip_address):
    """
    This function scans a single host using the ping command.
    It runs the ping command with the given IP address and checks the response.
    If the response contains "Received = 1", it means the host is up.
    Then it tries to get the IP address of the host using the socket.gethostbyname function.
    If the host is down or the ICMP packets are blocked, it prints an appropriate message.

    :param ip_address: str
        The IP address to scan.
    """
    # Scanning a host
    print ("**********************")
    print(colored (f"Scannen van host: {ip_address}", 'blue'))
    print ("**********************")
    response = subprocess.run(['ping', '-n', '1', '-w', '500', ip_address], stdout=subprocess.PIPE)             # run the ping command with the given IP address
    if "Received = 1" in response.stdout.decode('utf-8'):                                                       # check if the response contains "Received = 1"
        print(colored (f"{ip_address} is up", 'green'))                                                         # if yes, print that the host is up
        
        # IP-address search
        try:
            ip = socket.gethostbyname(ip_address)                                                               # try to get the IP address of the host
            print(f"IP-adres: {ip}")                                                                            # print the IP address
        except socket.gaierror:                                                                                 # if there is an error
            print(colored ("Ongeldige hostnaam", 'red', attrs=['bold']))                                        # print an error message
    else:                                                                                                       # if the response does not contain "Received = 1"
        print(colored (f"{ip_address} is down of de ICMP pakketjes worden geblokkeerd", 'red', attrs=['bold'])) # print that the host is down or the ICMP packets are blocked

# Get_mac_address
def get_mac_address(ip_address):
    """
    This function finds the MAC address of a given IP address using an ARP request.
    It creates an ARP request with the given IP address as the destination.
    Then it creates an Ethernet frame with the broadcast MAC address as the destination.
    It combines the Ethernet frame and ARP request into a single packet and sends it using the srp function.
    If a response is received, it returns the MAC address from the response.
    Otherwise, it returns None.

    :param ip_address: str
        The IP address to find the MAC address of.
    :return: str or None
        The MAC address of the given IP address or None if not found.
    """

    # ARP request to find the MAC address of the suspected IP address
    arp = ARP(pdst=ip_address)                                                      # create an ARP request with the given IP address as the destination
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")                                          # create an Ethernet frame with the broadcast MAC address as the destination
    packet = ether/arp                                                              # combine the Ethernet frame and ARP request into a single packet
    result = srp(packet, timeout=3, verbose=0)[0]                                   # send the packet using the srp function and get the response
    
    # return the found MAC address
    if result:                                                                      # if a response is received
        return result[0][1].hwsrc                                                   # return the MAC address from the response
    else:                                                                           # if no response is received
        return None                                                                 # return None

# Scan_tcp_ports
def scan_ports(ip_address):
    """
    This function scans a range of ports on a given IP address using multithreading.
    It divides the range of ports into smaller ranges based on the port_range parameter.
    For each smaller range of ports, it creates a thread for each port and starts it.
    Each thread calls the scan_port function with the IP address, port number, and open_ports list as arguments.
    After all the threads are done, it prints the open ports.
    """

    start_port = 1                                                                  # The starting port number to scan. Default is 1.
    end_port = 65535                                                                # The ending port number to scan. Default is 65535.   
    port_range = 4096                                                               # The number of ports to scan in each smaller range. Default is 4096 if you go higher means more threads usage.
    open_ports = []                                                                 # list to store the open ports
    threads = []                                                                    # list to store the threads

    print ("**********************")
    print (colored ("TCP poorten worden nu gescand in stukken van 4096", 'yellow'))
    print (colored ("De Scanner scant tot 65535", 'yellow')) 

    for i in range(start_port, end_port, port_range):                                           # divide the range of ports into smaller ranges
        port_start = i                                                                          # starting port number of the smaller range
        port_end = min(i + port_range, end_port)                                                # ending port number of the smaller range
        print(colored (f"- Scannen van poorten van {port_start} tot {port_end-1}", 'yellow'))   # print the smaller range of ports being scanned
        for port in range(port_start, port_end):                                                # for each port in the smaller range
            thread = threading.Thread(target=scan_port, args=(ip_address, port, open_ports))    # create a thread and set its target to the scan_port function
            threads.append(thread)                                                              # add the thread to the threads list
            thread.start()                                                                      # start the thread

        for thread in threads:                                                                  # for each thread in the threads list
            thread.join()                                                                       # wait for the thread to finish

    print ("**********************")    
    if not open_ports:                                                                          # if no open ports are found
        print(colored("Geen poorten gevonden", 'red', attrs=['bold']))                          # print an appropriate message
    else:                                                                                       # if open ports are found
        for port in open_ports:                                                                 # for each open port
            print(colored(f"Port {port}: open", 'green'))                                       # print that the port is open

# Scan_service
def scan_service(ip_address):
    """
    This function scans the services and ports on a given IP address using Nmap.
    It creates a PortScanner object and calls its scan method with the given IP address and arguments.
    Then it checks if the 'tcp' key is present in the scan results for the given IP address.
    If yes, it iterates over the ports in the 'tcp' key and checks if their state is 'open'.
    If yes, it prints the service name and port number.

    :param ip_address: str
        The IP address to scan.
    """
    try:
        print ("**********************")
        print (colored ("Service en de porten worden nu gescant doormiddel van Nmap", 'yellow'))

        scanner = nmap.PortScanner()                                                                            # create a PortScanner object
        scanner.scan(ip_address, arguments='-sS')                                                               # call its scan method with the given IP address and arguments
        if 'tcp' in scanner[ip_address]:                                                                        # check if the 'tcp' key is present in the scan results for the given IP address
            for port in scanner[ip_address]['tcp']:                                                             # iterate over the ports in the 'tcp' key
                if scanner[ip_address]['tcp'][port]['state'] == 'open':                                         # check if the port's state is 'open'
                    try:
                        service = scanner[ip_address]['tcp'][port]['name']                                      # get the service name
                        print(f"---------")
                        print(colored (f"Service: {service}", 'green' ))                                        # print the service name
                        print(colored (f"- port: {port}", 'green' ))                                            # print the port number

                    except KeyError:                                                                            # if there is a KeyError
                        pass                                                                                    # do nothing
    except nmap.PortScannerError:                                                                               # if there is a PortScannerError
        print(colored ("PortScannerError, besturingssysteem kan niet worden opgezocht",'red', attrs=['bold']))  # print an error message
        sys.exit()                                                                                              # exit the program

# Get Hostname 
def get_hostname(ip_address):
    """
    This function gets the hostname of a given IP address.
    It first gets the IP address of the given IP address using the socket.gethostbyname function.
    Then it tries to get the hostname of the IP address using the socket.gethostbyaddr function.
    If successful, it prints the hostname.
    Otherwise, it prints an error message and exits the program.

    :param ip_address: str
        The IP address to get the hostname of.
    """


    print ("**********************")
    ip = socket.gethostbyname(ip_address)                                                   # get the IP address of the given IP address
    print(colored(f"IP-adres: {ip}", 'green'))                                              # print the IP address

    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)                                                 # try to get the hostname of the IP address
    except socket.error:                                                                    # if there is an error
        print(colored("Ongeldige hostnaam", 'red', attrs=['bold']))                         # print an error message
        
    if hostname:
        oldhostname = hostname[:1]                                                          # get the first element of the hostname tuple
        newhostname = str(oldhostname)[1:-2]                                                # convert it to a string and remove the first and last characters
        newhostname = newhostname.replace("'", "")                                          # remove any single quotes
        print(colored(f"Hostname: {newhostname.strip()}", 'green'))                         # print the hostname
    else:
        print(colored("Kan geen hostnaam verkrijgen", 'red', attrs=['bold']))               # print the hostname when there is no hostname found

# Scan OS
def scan_os(ip_address):
    """
    This function scans the operating system of a given IP address using Nmap.
    It creates a PortScanner object and calls its scan method with the given IP address and arguments.
    Then it checks if the 'osmatch' key is present in the scan results for the given IP address.
    If yes, it prints the name of the operating system.
    Otherwise, it prints an appropriate message.

    :param ip_address: str
        The IP address to scan.
    """
    try:
        scanner = nmap.PortScanner()                                                                            # create a PortScanner object
        scanner.scan(ip_address, arguments='-O')                                                                # call its scan method with the given IP address and arguments
        osmatch = scanner[ip_address]['osmatch']                                                                # get the 'osmatch' key from the scan results for the given IP address
        if osmatch:                                                                                             # if the 'osmatch' key is present
            print(colored (f"Besturingssysteem: {osmatch[0]['name']}", 'green'))                                # print the name of the operating system
        else:                                                                                                   # if the 'osmatch' key is not present
            print(colored("Het Besturingssysteem kan niet worden gevonden", 'red', attrs=['bold']))             # print an appropriate message
    except nmap.PortScannerError:                                                                               # if there is a PortScannerError
        print(colored ("PortScannerError, besturingssysteem kan niet worden opgezocht", 'red', attrs=['bold'])) # print an error message
        sys.exit()                                                                                              # exit the program


# Choice subnetscan or hostscan
def subnet_scan(ip_address):
    """
    This function scans a subnet of IP addresses using the ping command.
    It first tries to create an IPv4Network object with the given IP address.
    If successful, it iterates over the hosts in the subnet and pings each host.
    If the response contains "Received = 1", it means the host is up and it prints an appropriate message.
    Otherwise, it prints that the host is down or the ICMP packets are blocked.

    :param ip_address: str
        The IP address and subnet mask in CIDR notation.
    """
    up_hosts = []
    try:
        subnet = ipaddress.ip_network(ip_address, strict=False)                                                 # try to create an IPv4Network object with the given IP address
    except ValueError:                                                                                          # if there is a ValueError
        print(colored ("Ongeldig IP-adres of subnetmasker", 'red', attrs=['bold']))                             # print an error message
        sys.exit()                                                                                              # exit the program
    
    # Scan hosts in subnet
    print(colored ( f"\nScannen van subnet {subnet}", 'blue'))                                                  # print the subnet being scanned
    for host in subnet.hosts():                                                                                 # iterate over the hosts in the subnet
        host = str(host)                                                                                        # convert the host to a string
        response = subprocess.run(['ping', '-n', '1', '-w', '500', host], stdout=subprocess.PIPE)               # run the ping command with the host as the destination
        if "Received = 1" in response.stdout.decode('utf-8'):                                                   # check if the response contains "Received = 1"
            print(colored (f"{host} is up", 'green'))                                                           # if yes, print that the host is up
            up_hosts.append(host)                                                                               # Make a up_hosts lists
        else:                                                                                                   # if no
            print(colored (f"{host} is down of de ICMP pakketjes worden geblokkeerd", 'red', attrs=['bold']))   # print that the host is down or the ICMP packets are blocked
    return up_hosts                                                                                             # return up_hosts

# hostscan
def host_scan(ip_address):
    """
    This function scans a single host using various methods.
    It first pings the host to check if it is up.
    If the host is up, it tries to get its IP address using the socket.gethostbyname function.
    Then it tries to get its MAC address using the get_mac_address function.
    After that, it scans the open TCP ports on the host using multithreading.
    Then it scans the services and ports on the host using Nmap.
    After that, it tries to get the hostname of the host using the socket.gethostbyaddr function.
    Finally, it tries to scan the operating system of the host using Nmap.

    :param ip_address: str
        The IP address to scan.
    """                           

# Scanning host
    print ("**********************")
    print(colored (f"Scannen van host: {ip_address}", 'blue'))
    print ("**********************")
    response = subprocess.run(['ping', '-n', '1', '-w', '500', ip_address], stdout=subprocess.PIPE)             # run the ping command with the given IP address
    if "Received = 1" in response.stdout.decode('utf-8'):                                                       # check if the response contains "Received = 1"           
        #print(colored (f"{ip_address} is up", 'green'))
        
# IP-address search
        try:
            ip = socket.gethostbyname(ip_address)                                                               # try to get the IP address of the host
        except socket.gaierror:                                                                                 # if there is an error
            print(colored ("Ongeldige hostnaam", 'red', attrs=['bold']))                                        # print an error message
    else:                                                                                                       # if the response does not contain "Received = 1"
        print(colored (f"{ip_address} is down of de ICMP pakketjes worden geblokkeerd", 'red', attrs=['bold'])) # print that the host is down or the ICMP packets are blocked

# MAC-address search and check
    mac_address = get_mac_address(ip_address)                                                                   # try to get the MAC address of the host
    print(f'MAC address: {mac_address}')                                                                        # print the MAC address

# Scanning open ports
    open_ports = []                                                                 # list to store the open ports
    threads = []                                                                    # list to store the threads
    start_port = 1                                                                  # The starting port number to scan. Default is 1.
    end_port = 65535                                                                # The ending port number to scan. Default is 65535.   
    port_range = 4096                                                               # The number of ports to scan in each smaller range. Default is 4096 if you go higher means more threads usage.
    print ("**********************")
    print (colored ("TCP poorten worden nu gescand in stukken van 4096", 'yellow'))
    print (colored ("De Scanner scant tot 65535", 'yellow')) 
    for i in range(start_port, end_port, port_range):                                           # divide the range of ports into smaller ranges based on port_range
        port_start = i                                                                          # starting port number of the smaller range
        port_end = min(i + port_range, end_port)                                                # ending port number of the smaller range
        print(colored (f"- Scannen van poorten van {port_start} tot {port_end-1}", 'yellow'))   # print the smaller range of ports being scanned
        for port in range(port_start, port_end):                                                # for each port in the smaller range
            thread = threading.Thread(target=scan_port, args=(ip_address, port, open_ports))    # create a thread and set its target to scan_port function with ip_address, port and open_ports as arguments
            threads.append(thread)                                                              # add thread to threads list 
            thread.start()                                                                      # Start thread 

        for thread in threads:
            thread.join()

    print ("**********************")
    if not open_ports:
        print(colored("Geen poorten gevonden", 'red', attrs=['bold']))
    else:
        for port in open_ports:
            print(colored(f"Port {port}: open", 'green'))

 # searching service:
    try:
        print ("**********************")
        print (colored ("Service en de poorten worden nu gescand doormiddel van Nmap", 'yellow'))

        scanner = nmap.PortScanner()                                                                            # create a PortScanner object
        scanner.scan(ip_address, arguments='-sS')                                                               # call its scan method with the given IP address and arguments
        if 'tcp' in scanner[ip_address]:                                                                        # check if the 'tcp' key is present in the scan results for the given IP address
            for port in scanner[ip_address]['tcp']:                                                             # iterate over the ports in the 'tcp' key
                if scanner[ip_address]['tcp'][port]['state'] == 'open':                                         # check if the port's state is 'open'
                    try:
                        service = scanner[ip_address]['tcp'][port]['name']                                      # get the service name
                        print(f"---------")
                        print(colored (f"Service: {service}", 'green' ))                                        # print the service name
                        print(colored (f"- port: {port}", 'green' ))                                            # print the port number

                    except KeyError:
                        pass
    except nmap.PortScannerError:                                                                               # if there is a KeyError
        print(colored ("PortScannerError, besturingssysteem kan niet worden opgezocht",'red', attrs=['bold']))  # print an error message
        sys.exit()                                                                                              # exit the program
            
# searching hostnames
    print ("**********************")
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(ip)                                                 # try to get the hostname of the IP address
    except socket.error:                                                                    # if there is an error
        print(colored("Error", 'red', attrs=['bold']))                                      # print an error message
        
    if hostname:
        oldhostname = hostname[:1]                                                          # get the first element of the hostname tuple
        newhostname = str(oldhostname)[1:-2]                                                # convert it to a string and remove the first and last characters
        newhostname = newhostname.replace("'", "")                                          # remove any single quotes
        print(colored(f"Hostname: {newhostname.strip()}", 'green'))                         # print the hostname
    else:
        print(colored("Kan geen hostnaam verkrijgen", 'red', attrs=['bold']))               # print the hostname when there is no hostname found

# searching OS
    try:    
        scanner = nmap.PortScanner()                                                                            # create a PortScanner object
        scanner.scan(ip_address, arguments='-O')                                                                # call its scan method with the given IP address and arguments
        osmatch = scanner[ip_address]['osmatch']                                                                # get the 'osmatch' key from the scan results for the given IP address
        if osmatch:                                                                                             # if the 'osmatch' key is present
            print(colored (f"Besturingssysteem: {osmatch[0]['name']}", 'green'))                                # print the name of the operating system
        else:                                                                                                   # if the 'osmatch' key is not present
            print(colored ("Het Besturingssysteem kan niet worden gevonden" ,'red', attrs=['bold']))            # print an appropriate message
    except nmap.PortScannerError:                                                                               # if there is a PortScannerError
        print(colored ("PortScannerError, besturingssysteem kan niet worden opgezocht", 'red', attrs=['bold'])) # print an error message
        sys.exit()                                                                                              # exit the program


# main
def main():
    """
    Runs the main function of the Emma en Rudy Networkscan program.

    This function displays a menu and asks the user to select an action to perform. Based on the user's choice, it will call
    the appropriate function to perform a subnetmask scan, a host scan or a combination of subnet and host scans.
    """
    index = 0
    while True:
        # show the menu for the choices
        print(colored("**********************", 'blue'))
        print(colored("Welkom bij Emma en Rudy Networkscan", 'blue'))
        print(colored("**********************", 'blue'))
        print("Welke actie wilt u uitvoeren?")
        print("1. Subnetmask scan")
        print("2. Host scan")
        print("3. Combinaties subnets en hosts scannen")
        choice = input("Maak uw keuze tussen 1, 2 of 3: ")

        if choice == '1': #choice 1                                                                                                  
            while True:
                ip_input = input("Voer een subnetmasker in (bijv. 192.168.1.0/24): ")
                if not ip_input:
                    print(colored("Je hebt niets ingevuld. Probeer het opnieuw.", 'red', attrs=['bold']))
                    continue
                if '/' not in ip_input:
                    print(colored("Je hebt geen prefixlengte toegevoegd. Probeer het opnieuw.", 'red', attrs=['bold']))
                    continue
                try:
                    subnet = ipaddress.ip_network(ip_input, strict=False)
                    break
                except ValueError:
                    print(colored("Het ingevulde subnetmasker is ongeldig. Probeer het opnieuw.", 'red', attrs=['bold']))
                    continue
            subnet_scan(subnet)

        elif choice == '2': # choice 2
            # Ask for a IP address and make sure the input is right om een 
            while True:
                try:
                    ip_input = input("Voer een IP-adres in (bijv. 192.168.1.100): ")
                    ip_address = ipaddress.ip_address(ip_input)
                    ip_address_str = str(ip_address)
                    host_scan(ip_address_str)
                    break
                except ValueError:
                    print(colored ("Ongeldig IP-adres, probeer het opnieuw.", 'red', attrs=['bold']))
            break

        elif choice == '3': # choice 3
            # Ask for a subnetmask and make sure the input is right
            while True:
                try:
                    ip_input = input("Voer een subnetmasker in (bijv. 192.168.1.0/24): ")
                    subnet = ipaddress.ip_network(ip_input)
                    up_hosts = subnet_scan(subnet)
                    print(colored(f"De hosts die up zijn: {up_hosts}", 'green'))

                    for i in range(len(up_hosts)):
                        ip = up_hosts[i]
                        print ("**********************")
                        print(colored (f"Scannen van host: {ip}", 'blue'))
                        print ("**********************")

                        mac_address = get_mac_address(ip)
                        print(f'MAC address: {mac_address}')
                        scan_ports(ip)
                        scan_service(ip)
                        get_hostname(ip)
                        scan_os(ip)
                        if i < len(up_hosts)-1:
                            print(colored("Wachten op de volgende positie in de lijst...", 'yellow'))
                    print("Alles is gescand")
                    main()
                    
                except ValueError: # error message
                    print(colored("Ongeldig subnetmasker, probeer het opnieuw.", 'red', attrs=['bold']))

main()