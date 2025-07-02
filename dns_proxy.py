import socket
import json
import sys

CONFIG_FILE = "dns_config.json"
MAX_DNS_PACKET_SIZE = 512


def load_config(path):
    with open(path, 'r') as f:
        return json.load(f)


def extract_domain_name(data):
    domain_parts = []
    idx = 12
    length = data[idx]

    while length != 0:
        idx += 1
        domain_parts.append(data[idx:idx+length].decode())
        idx += length
        length = data[idx]

    return '.'.join(domain_parts)


def build_block_response(request, block_type, block_ip=None):
    h_id=request[:2]    

    #these are 0x values for universal DNS query/response header flags I found on the internet 
    if block_type == "not_found":
        h_flags = b'\x81\x83' 
    elif block_type == "refused":
        h_flags = b'\x81\x85'    
    elif block_type == "redirected_domain":
        h_flags = b'\x81\x80'  
    else:
        raise ValueError("Unknown block_type")      
    
    h_qdcount = b'\x00\x01'   
    h_ancount = b'\x00\x01' if block_type=="redirected_domain" else b'\x00\x00'   
    h_nscount = b'\x00\x00'   
    h_arcount = b'\x00\x00'
       
    header = h_id + h_flags + h_qdcount + h_ancount + h_nscount + h_arcount
    question = request[12:]

    if block_type != "redirected_domain":
        return header + question

    name_pointer = b'\xc0\x0c'        
    type_a = b'\x00\x01'               
    class_in = b'\x00\x01'             
    ttl = b'\x00\x00\x00\x3c'          
    rdlength = b'\x00\x04'             
    rdata = socket.inet_aton(block_ip) 
    answer = name_pointer + type_a + class_in + ttl + rdlength + rdata
   
    return header + question + answer
    

def forward_to_upstream(request, upstream_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
        upstream_sock.settimeout(2)
        upstream_sock.sendto(request, (upstream_ip, 53))
        try:
            response, _ = upstream_sock.recvfrom(MAX_DNS_PACKET_SIZE)
            return response
        except socket.timeout:
            return b''


def start_dns_proxy(config):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))
    print("DNS Proxy Server is running on 127.0.0.1:53...")

    blacklist = config.get("blacklist", {})
    upstream_dns = config.get("upstream_dns", "8.8.8.8")

    while True:
        try:
            data, client_addr = sock.recvfrom(MAX_DNS_PACKET_SIZE)
            domain = extract_domain_name(data)
            print(f"Received DNS query for: {domain}")           

            is_domain_blocked = None
            for blocked in blacklist:
                if blocked.lower() in domain:
                    is_domain_blocked = blacklist[blocked]
                    break

            if is_domain_blocked:
                block_type = blacklist[domain]['type']
                block_ip = blacklist[domain].get('ip')  
                print(f"Blocked domain: {domain}. Type: {block_type}")
                response = build_block_response(data, block_type, block_ip)
            else:
                response = forward_to_upstream(data, upstream_dns)

            sock.sendto(response, client_addr)

        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    try:
        config = load_config(CONFIG_FILE)
        start_dns_proxy(config)
    except PermissionError:
        print(" Run the script with root!")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Configuration file '{CONFIG_FILE}' not found.")
        sys.exit(1)

