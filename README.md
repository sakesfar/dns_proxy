# DNX Proxy server
Simple DNS proxy server that redirects dns queries to localhost and blocks unwantend domains

1. mdkir -p ~/dns_proxy && cd ~/dns_proxy
2. git clone https://github.com/sakesfar/dns_proxy 
2. Ensure `/etc/resolv.conf` has this inside: `nameserver 127.0.0.1`
3. Run command: `python3 dns_proxy.py`

## Concept behind
Before a proper TCP/IP packet with payload data is generated, a DNS query is formed. DNS server is generally supplied by your IPS.
The idea is to route DNS queries throguh our DNS proxy server ( we tie it to _localhost_ `127.0.0.1`) and extract `domain` part of the query and check against our blacklist. Simple :)

