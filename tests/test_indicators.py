from cipher.core.indicators import extract_urls
from cipher.core.indicators import extract_ipv4_addresses
from cipher.core.indicators import extract_domains



content = """
Visit https://example.com/login
Contact 192.168.1.10
Connect to 8.8.8.8
Invalid address 192.999.1.1
"""

addresses = extract_ipv4_addresses(content)

print("IPv4 addresses found:")

for address in addresses:
    print(" -", address)


content = """
Visit https://example.com/login
Download from http://test.example.org/file
Contact server.example.net
"""

domains = extract_domains(content)

print("Domains found:")

for domain in domains:
    print(" -", domain)



content = """
Visit https://example.com/login
Download from http://test.example.org/file
https://example.com/login
"""

urls = extract_urls(content)

print("URLs found:")

for url in urls:
    print(" -", url)