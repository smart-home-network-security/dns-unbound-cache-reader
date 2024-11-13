from enum import Enum, IntEnum
import re
import subprocess
from fabric import Connection, Config


## Global variables
# Localhost IP addresses
localhost = [
    "localhost",
    "127.0.0.1",
    "::1",
    "0000:0000:0000:0000:0000:0000:0000:0001"
]
# Shell command to get the DNS cache
cmd = "unbound-control dump_cache"
# Strings to skip in the DNS cache
to_skip = (
    ";",
    "START",
    "END",
    "EOF"
)
# Regex patterns
pattern_line      = r"^([a-zA-Z0-9.-]+)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$"                    # Generic DNS cache line
pattern_ipv4_byte = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"                          # Single byte from an IPv4 address
pattern_ptr       = (pattern_ipv4_byte + r"\.") * 3 + pattern_ipv4_byte + r".in-addr.arpa"  # Reverse DNS lookup qname
pattern_srv       = r"^(\d+)\s+(\d+)\s+(\d+)\s+([a-zA-Z0-9.-]+)$"                           # SRV record target


class DnsCacheSection(Enum):
    """
    Enum class for the strings indicating the relevant sections in the DNS cache.
    """
    START_RRSET = "START_RRSET_CACHE"
    END_RRSET   = "END_RRSET_CACHE"


class DnsRtype(IntEnum):
    """
    Enum class for the DNS resource record types.
    """
    A    = 1   # IPv4 address
    NS   = 2   # Name server
    PTR  = 12  # Domain name pointer
    AAAA = 28  # IPv6 address
    SRV  = 33  # Service locator


class DnsTableKeys(Enum):
    """
    Enum class for the allowed dictionary keys.
    """
    IP      = "ip"
    SERVICE = "service"


def read_unbound_cache(host: str = "127.0.0.1"):
    """
    Read the Unbound DNS cache and return it as a dictionary,
    in the format:
        {
            DnsTableKeys.IP: {
                ip_address: domain_name,
                ...
            },
            DnsTableKeys.SERVICE: {
                service_name: actual_name,
                ...
            }
        }

    Args:
        host (str): IP address of the Unbound DNS server. Default is localhost.
    """
    if host in localhost:
        ## Unbound runs on localhost
        proc = subprocess.run(cmd.split(), capture_output=True)
        dns_cache = proc.stdout.decode().strip().split("\n")

    else:
        ## Unbound runs on a remote host
        # SSH connection with remote host
        ssh_config = Config(overrides={"run": {"hide": True}})
        remote = Connection(host, config=ssh_config)
        # Get the DNS cache
        result = remote.run(cmd)
        dns_cache = result.stdout.strip().split("\n")
    

    ### Parse DNS cache ###

    # Find start and end indices of RRSET section
    try:
        start_idx = dns_cache.index(DnsCacheSection.START_RRSET.value)
        end_idx   = dns_cache.index(DnsCacheSection.END_RRSET.value)
    except ValueError:
        start_idx = 0
        end_idx   = len(dns_cache)

    # Loop through the RRSET section
    dns_table = {}
    for line in dns_cache[start_idx+1:end_idx]:

        # Lines containing metadata, skip
        if line.startswith(to_skip):
            continue

        # Parse line with regex
        match = re.match(pattern_line, line)
        
        # No regex match, skip line
        if not match:
            continue

        name  = match.group(1)
        if name.endswith("."):
            name = name[:-1]
        rtype = match.group(3)
        rdata = match.group(4)
        if rdata.endswith("."):
            rdata = rdata[:-1]

        # rtype not in allowed list, skip line
        if rtype not in DnsRtype._member_names_:
            continue


        ## Parse supported records

        # A (IPv4) and AAAA (IPv6) records
        if rtype == DnsRtype.A.name or rtype == DnsRtype.AAAA.name:
            ip = rdata
            if DnsTableKeys.IP in dns_table:
                dns_table[DnsTableKeys.IP][ip] = name
            else:
                dns_table[DnsTableKeys.IP] = {ip: name}

        # PTR records
        if rtype == DnsRtype.PTR.name:
            match_ptr = re.match(pattern_ptr, name)
            if match_ptr:
                # PTR record is a reverse DNS lookup
                ip = ".".join(reversed(match_ptr.groups()))
                if ip not in dns_table.get(DnsTableKeys.IP, {}):
                    if DnsTableKeys.IP in dns_table:
                        dns_table[DnsTableKeys.IP][ip] = rdata
                    else:
                        dns_table[DnsTableKeys.IP] = {ip: rdata}
            else:
                # PTR record contains generic RDATA
                if DnsTableKeys.SERVICE in dns_table:
                    dns_table[DnsTableKeys.SERVICE][name] = rdata
                else:
                    dns_table[DnsTableKeys.SERVICE] = {name: rdata}

        # SRV records
        if rtype == DnsRtype.SRV.name:
            # Parse target service
            match_srv = re.match(pattern_srv, rdata)
            if not match_srv:
                continue
            service = match_srv.group(4)
            if service.endswith("."):
                service = service[:-1]
            if DnsTableKeys.SERVICE in dns_table:
                dns_table[DnsTableKeys.SERVICE][service] = name
            else:
                dns_table[DnsTableKeys.SERVICE] = {service: name}


    return dns_cache
