
ROOT_SERVERS = (
    'A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4',
    'B.ROOT-SERVERS.NET. 3600000 A 192.228.79.201',
    'C.ROOT-SERVERS.NET. 3600000 A 192.33.4.12',
    'D.ROOT-SERVERS.NET. 3600000 A 199.7.91.13',
    'E.ROOT-SERVERS.NET. 3600000 A 192.203.230.10',
    'F.ROOT-SERVERS.NET. 3600000 A 192.5.5.241',
    'G.ROOT-SERVERS.NET. 3600000 A 192.112.36.4',
    'H.ROOT-SERVERS.NET. 3600000 A 128.63.2.53',
    'I.ROOT-SERVERS.NET. 3600000 A 192.36.148.17',
    'J.ROOT-SERVERS.NET. 3600000 A 192.58.128.30',
    'K.ROOT-SERVERS.NET. 3600000 A 193.0.14.129',
    'L.ROOT-SERVERS.NET. 3600000 A 199.7.83.42',
    'M.ROOT-SERVERS.NET. 3600000 A 202.12.27.33'
)

RFC1035_TYPES = {
    0x0001: 'A',  # Host Address
    0x0002: 'NS',  # Authoritative Name Server
    0x0005: 'CNAME',  # Canonical Name Cor an Alias
    0x0006: 'SOA',  # Start Zone of Authority
    0x000f: 'MX',  # Mail Exchange
    0x0010: 'TXT',  # Text Strings
    0x001c: 'AAAA',  # IPv6 address
    #0x0029: 'OPT', # <ROOT> OPT
}

'''REPLY_CODE'''
NOERROR = 0  # DNS Query completed successfully
NXDOMAIN = 3 # Domain name does not exist
