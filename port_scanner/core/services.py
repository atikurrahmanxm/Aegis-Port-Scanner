"""
Well-known port dictionary, Nmap-aligned top port lists,
and service probing heuristics.
"""

from typing import Dict, List, Optional

# Mapping of port number to standard service name
COMMON_SERVICES: Dict[int, str] = {
    7: "Echo",
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    43: "WHOIS",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-Name",
    138: "NetBIOS-Datagram",
    139: "NetBIOS-Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Submission",
    631: "IPP (CUPS)",
    636: "LDAPS",
    873: "Rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS-Proxy",
    1194: "OpenVPN",
    1433: "Microsoft-SQL",
    1434: "Microsoft-SQL-Monitor",
    1521: "Oracle-DB",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2181: "ZooKeeper",
    2222: "DirectAdmin / SSH-Alt",
    3000: "NodeJS / React-Dev / Grafana",
    3128: "Squid-Proxy",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4369: "Erlang-Port-Mapper",
    5000: "Flask / Docker-Registry",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6667: "IRC",
    7000: "Cassandra",
    8000: "HTTP-Alt / Django-Dev",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy / Apache-Tomcat",
    8081: "HTTP-Alt / Blackice-Icecap",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt / Jupyter",
    9000: "SonarQube / PHP-FPM",
    9090: "Prometheus",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    50000: "SAP",
}

# Top 20 ports based on statistical exposure
TOP_20_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

# Top 100 ports based on Nmap frequency metrics
TOP_100_PORTS: List[int] = sorted(list(set(TOP_20_PORTS + [
    7, 9, 13, 20, 26, 37, 43, 53, 69, 79, 81, 88, 102, 113, 119, 123,
    137, 138, 161, 179, 264, 311, 389, 427, 444, 464, 465, 497, 500,
    512, 513, 514, 515, 524, 541, 548, 554, 587, 616, 623, 631, 636,
    646, 689, 777, 787, 800, 808, 873, 902, 990, 1025, 1026, 1080,
    1194, 1214, 1433, 1434, 1521, 1720, 1812, 1863, 1900, 2000, 2049,
    2082, 2083, 2121, 2181, 2222, 2601, 2604, 3000, 3128, 3268, 3306,
    3389, 3690, 4000, 4899, 5000, 5001, 5060, 5432, 5555, 5672, 5900,
    6000, 6001, 6379, 6667, 7000, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9090, 9100, 9200, 9999, 10000, 11211, 27017
])))

# Top 1000 ports: includes TOP_100 plus next most common services and port blocks
def _generate_top_1000() -> List[int]:
    ports = set(TOP_100_PORTS)
    # Standard server and appliance ranges
    ports.update(range(1, 1025))  # Well-known privileged ports 1-1024
    # Additional high-profile web, game, and cloud ports
    extra_common = [
        1080, 1194, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 
        2375, 2376, 2483, 2484, 3000, 3128, 3306, 3389, 3690, 4000, 4243, 
        4369, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 6667, 7000, 
        7001, 7474, 8000, 8008, 8080, 8081, 8088, 8443, 8500, 8888, 9000, 
        9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211, 
        27017, 27018, 28017, 50000, 50070
    ]
    ports.update(extra_common)
    return sorted(list(ports))[:1000]

TOP_1000_PORTS: List[int] = _generate_top_1000()


def get_service_name(port: int) -> str:
    """Get standard service name for port or 'Unknown'."""
    return COMMON_SERVICES.get(port, "Unknown")


def get_top_ports(count: int = 100) -> List[int]:
    """Retrieve top N ports list."""
    if count <= 20:
        return TOP_20_PORTS[:count]
    elif count <= 100:
        return TOP_100_PORTS[:count]
    else:
        return TOP_1000_PORTS[:count]


def get_probe_payload(port: int, host: str = "target") -> Optional[bytes]:
    """
    Return service-specific payload to trigger a responsive banner safely.
    """
    # HTTP / HTTPS / Web proxies
    if port in {80, 8080, 8000, 8081, 8888, 3000, 5000, 9000, 9090}:
        return f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: AegisScan/1.0\r\nAccept: */*\r\n\r\n".encode("utf-8")
    
    # HTTPS / SSL ports (sending TLS ClientHello or simple HTTP)
    if port in {443, 8443, 9443}:
        return f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: AegisScan/1.0\r\n\r\n".encode("utf-8")
    
    # Redis
    if port == 6379:
        return b"PING\r\n"
        
    # Memcached
    if port == 11211:
        return b"stats\r\n"
        
    # SMTP / Mail submission
    if port in {25, 587}:
        return b"EHLO scan.local\r\n"
        
    # Generic probing for other interactive services
    return b"\r\n"
