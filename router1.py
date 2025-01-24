import socket
import threading
import csv
import time
import ipaddress

HOST = '127.0.0.1'

# Read forwarding table for the router
def load_forwarding_table(filename):
    forwarding_table = []
    try:
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) != 4:
                    print(f"Invalid entry in forwarding table: {row}")
                    continue
                
                network_dest, netmask, gateway, interface = row
                
                try:
                    # Validate gateway and interface
                    socket.inet_aton(gateway)  # Check if gateway is a valid IP address
                    
                    if not interface.strip():
                        raise ValueError(f"Invalid interface: {interface}")
                    
                    # Add valid entry to the forwarding table
                    forwarding_table.append({
                        'network_dest': network_dest.strip(),
                        'netmask': netmask.strip(),
                        'gateway': gateway.strip(),
                        'interface': interface.strip()
                    })
                except Exception as e:
                    print(f"Skipping invalid forwarding entry: {row}. Error: {e}")
                    continue
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
    return forwarding_table

# Parse incoming packet
def parse_packet(packet):
    try:
        print(f"Received packet: {packet}")
        packet = packet.strip('{}')
        source_ip, dest_ip, payload, ttl = packet.split(',')
        ttl = ttl.split(":")[-1].strip()
        return {
            'source_ip': source_ip.strip(),
            'dest_ip': dest_ip.strip(),
            'payload': payload.strip(),
            'ttl': int(ttl)
        }
    except Exception as e:
        print(f"Error parsing packet: {packet}. Error: {e}")
        return None

# Match the destination IP against the forwarding table entry
def check_forwarding_table(dest_ip, forwarding_table):
    for entry in forwarding_table:
        network_dest = entry['network_dest']
        netmask = entry['netmask']
        gateway = entry['gateway']
        interface = entry['interface']
        
        # Convert to IP address objects for matching
        network_ip = ipaddress.IPv4Network(f"{network_dest}/{netmask}", strict=False)
        dest_ip_obj = ipaddress.IPv4Address(dest_ip)
        
        if dest_ip_obj in network_ip:
            print(f"Match found in forwarding table: {entry}")
            return {'gateway': gateway, 'interface': interface}
    
    # Default gateway (interface 0.0.0.0)
    print(f"No direct match found for destination IP {dest_ip}. Using default gateway.")
    return {'gateway': '0.0.0.0', 'interface': '127.0.0.1'}

# Forward packet based on routing decisions
def forward_packet(router_num, packet, forwarding_table):
    if not packet:
        return
    
    dest_ip = packet['dest_ip']
    ttl = packet['ttl']

    # Decrement TTL
    ttl -= 1
    if ttl <= 0:
        with open(f"discarded_by_router_{router_num}.txt", 'a') as f:
            f.write(f"Packet with TTL=0 discarded: {packet['payload']}\n")
        return

    # Check forwarding table for a matching entry
    forwarding_decision = check_forwarding_table(dest_ip, forwarding_table)

    if forwarding_decision['interface'] == '127.0.0.1':
        # Final destination, no next hop
        with open(f"out_router_{router_num}.txt", 'a') as f:
            f.write(f"Packet for final destination: {packet['payload']} TTL={ttl}\n")
    else:
        # Forward to the next hop
        gateway = forwarding_decision['gateway']
        interface = forwarding_decision['interface']

        # Log sent packet
        with open(f"sent_by_router_{router_num}.txt", 'a') as f:
            f.write(f"Packet: {packet['payload']} TTL={ttl} to Router {gateway}\n")
        
        # Send packet over the socket to the next router
        send_packet(gateway, interface, packet, ttl)

# Send packet over socket to next hop router
def send_packet(gateway, interface, packet, ttl):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, int(interface)))  # Interface is the port number
            packet_data = f"{packet['source_ip']},{packet['dest_ip']},{packet['payload']},TTL:{ttl}"
            s.sendall(packet_data.encode('utf-8'))
            print(f"Sent packet to Router {gateway} on port {interface}")
    except Exception as e:
        print(f"Error sending packet to Router {gateway}: {e}")

# Function to handle receiving packets
def handle_received_packet(router_num, packet, forwarding_table):
    if not packet:
        return
    with open(f"received_by_router_{router_num}.txt", 'a') as f:
        f.write(f"Received: {packet['payload']} from {packet['source_ip']}\n")
    forward_packet(router_num, packet, forwarding_table)

# Function to start listening for connections (simulating the router server)
def router_server(router_num, port, forwarding_table):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()
        print(f"Router {router_num} listening on port {port}...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_connection, args=(router_num, conn, forwarding_table), daemon=True).start()

def handle_connection(router_num, conn, forwarding_table):
    with conn:
        try:
            data = conn.recv(1024)
            if data:
                packet = parse_packet(data.decode('utf-8'))
                handle_received_packet(router_num, packet, forwarding_table)
        except Exception as e:
            print(f"Error handling connection: {e}")

# Main function to start router
def main():
    router_num = 1
    forwarding_table = load_forwarding_table(f'router_1_table.csv')

    if not forwarding_table:
        print("No valid forwarding table loaded. Exiting...")
        return

    ports = [8001, 8002]
    for port in ports:
        threading.Thread(target=router_server, args=(router_num, port, forwarding_table), daemon=True).start()

    with open('packets.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            packet = parse_packet(','.join(row))
            if packet:
                print(f"Sending packet: {packet['payload']} TTL={packet['ttl']} to Router 2")
                with open(f"sent_by_router_{router_num}.txt", 'a') as out_file:
                    out_file.write(f"{packet['payload']} TTL={packet['ttl']} to Router 2\n")
                send_packet('127.0.0.1', 8002, packet, packet['ttl'])
                time.sleep(1)

if __name__ == "__main__":
    main()
