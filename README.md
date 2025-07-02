# DNX Proxy server
Simple DNS proxy server that redirects dns queries to localhost and blocks unwantend domains

**Instructions to run the dns proxy server:**
1.  `cd /path/to/your/projectsFile`
2. `git clone https://github.com/sakesfar/dns_proxy `
3. `cd dns_proxy`
4. Ensure `/etc/resolv.conf` has this inside: `nameserver 127.0.0.1`
5. `python3 dns_proxy.py`

## Concept behind
Before a proper TCP/IP packet with payload data is generated, a DNS query is formed. DNS server is generally supplied by your IPS.
The idea is to route DNS queries throguh our DNS proxy server ( we tie it to _localhost_ `127.0.0.1`) and extract `domain` part of the query and check against our blacklist. Simple :)

