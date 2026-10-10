Author: Manjushree D

 Scripts
 
 1. dns-custom-recon.nse
Enhances Nmap's built-in `dns-recursion` script. Instead of only checking
whether a DNS server allows recursive queries, it polls the target DNS server
for six attributes in a single pass and reports each as FOUND / NOT FOUND:

- IPv4 Address (A record)
- IPv6 Address (AAAA record)
- Name Servers (NS record)
- Start of Authority (SOA record)
- Mail Servers (MX record)
- DNSSEC validation support

 2. ssh-scanner.nse
Connects to TCP port 22, reads the SSH identification banner, and reports:

- SSH banner string
- Protocol version (SSHv1 vs SSHv2)
- Software fingerprint (e.g. OpenSSH)

 Installation

```bash
sudo cp dns-custom-recon.nse ssh-scanner.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

 Usage

```bash
# DNS multi-record discovery
sudo nmap -sU -p 53 --script dns-custom-recon 8.8.8.8

# SSH banner discovery
sudo nmap -p 22 --script ssh-scanner localhost
```

 License
Same as Nmap — see https://nmap.org/book/man-legal.html
