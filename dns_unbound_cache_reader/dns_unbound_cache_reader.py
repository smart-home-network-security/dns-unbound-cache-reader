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
pattern_line      = r"^([a-zA-Z0-9._-]+)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$"                   # Generic DNS cache line
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
    A     = 1   # IPv4 address
    CNAME = 5   # Canonical name
    PTR   = 12  # Domain name pointer
    AAAA  = 28  # IPv6 address
    SRV   = 33  # Service locator


class DnsTableKeys(Enum):
    """
    Enum class for the allowed dictionary keys.
    """
    IP    = "ip"
    ALIAS = "alias"


def update_dns_table(
        dns_table: dict = {},
        host: str = "127.0.0.1",
        file: str = None
    ) -> dict:
    """
    Update the given DNS table by reading the current DNS cache.

    Args:
        dns_table (dict): Dictionary containing the current DNS table.
        host (str): IP address of the Unbound DNS server. Default is localhost.
        file (str): Path to a file containing the Unbound DNS cache. Default is None.
                    If specified, the function reads the cache from the file instead of the server.
    Returns:
        dict: Updated DNS table.
    """
    ### Get DNS cache ###
    dns_cache = None

    if file is None:
        # Get DNS cache from Unbound

        if host in localhost:
            ## Unbound runs on localhost
            proc = subprocess.run(cmd.split(), capture_output=True, text=True)
            dns_cache = proc.stdout.strip().split("\n")
            del proc

        else:
            ## Unbound runs on a remote host
            # SSH connection with remote host
            ssh_config = Config(overrides={"run": {"hide": True}})
            with Connection(host, config=ssh_config) as remote:
                # Get the DNS cache
                result = remote.run(cmd, warn=True)
                if not result.failed:
                    dns_cache = result.stdout.strip().split("\n")
                # Free resources
                del result

    else:
        # Read DNS cache from file
        with open(file, "r") as f:
            dns_cache = f.read().strip().split("\n")


    ### Parse DNS cache ###

    # Find start and end indices of RRSET section
    try:
        start_idx = dns_cache.index(DnsCacheSection.START_RRSET.value)
        end_idx   = dns_cache.index(DnsCacheSection.END_RRSET.value)
    except ValueError:
        start_idx = 0
        end_idx   = len(dns_cache)

    # Loop through the RRSET section
    for line in dns_cache[start_idx+1:end_idx]:

        # Lines containing metadata, skip
        if line.startswith(to_skip):
            continue

        # Parse line with regex
        match = re.match(pattern_line, line)
        
        # No regex match, skip line
        if not match:
            continue

        qname  = match.group(1)
        if qname.endswith("."):
            qname = qname[:-1]
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
            if DnsTableKeys.IP.name in dns_table:
                dns_table[DnsTableKeys.IP.name][ip] = qname
            else:
                dns_table[DnsTableKeys.IP.name] = {ip: qname}

        # CNAME records
        if rtype == DnsRtype.CNAME.name:
            cname = rdata
            if DnsTableKeys.ALIAS.name in dns_table:
                dns_table[DnsTableKeys.ALIAS.name][cname] = qname
            else:
                dns_table[DnsTableKeys.ALIAS.name] = {cname: qname}

        # SRV records
        if rtype == DnsRtype.SRV.name:
            # Parse target service
            match_srv = re.match(pattern_srv, rdata)
            if not match_srv:
                continue
            service = match_srv.group(4)
            if service.endswith("."):
                service = service[:-1]
            if DnsTableKeys.ALIAS.name in dns_table:
                dns_table[DnsTableKeys.ALIAS.name][service] = qname
            else:
                dns_table[DnsTableKeys.ALIAS.name] = {service: qname}

        # PTR records
        if rtype == DnsRtype.PTR.name:
            match_ptr = re.match(pattern_ptr, qname)
            if match_ptr:
                # PTR record is a reverse DNS lookup
                ip = ".".join(reversed(match_ptr.groups()))
                if ip not in dns_table.get(DnsTableKeys.IP.name, {}):
                    if DnsTableKeys.IP.name in dns_table:
                        dns_table[DnsTableKeys.IP.name][ip] = rdata
                    else:
                        dns_table[DnsTableKeys.IP.name] = {ip: rdata}
            else:
                # PTR record contains generic RDATA
                ptr = rdata
                if DnsTableKeys.ALIAS.name in dns_table:
                    dns_table[DnsTableKeys.ALIAS.name][qname] = ptr
                else:
                    dns_table[DnsTableKeys.ALIAS.name] = {qname: ptr}


    ## Post-processing
    # Replace all cnames with aliases
    if DnsTableKeys.IP.name in dns_table and DnsTableKeys.ALIAS.name in dns_table:
        for ip, cname in dns_table[DnsTableKeys.IP.name].items():
            if cname in dns_table[DnsTableKeys.ALIAS.name]:
                dns_table[DnsTableKeys.IP.name][ip] = dns_table[DnsTableKeys.ALIAS.name][cname]


    return dns_table



def read_dns_cache(
        host: str = "127.0.0.1",
        file: str = None
    ) -> dict:
    """
    Read the Unbound DNS cache and return it as a dictionary,
    in the format:
        {
            DnsTableKeys.IP: {
                ip_address: domain_name,
                ...
            },
            DnsTableKeys.ALIAS: {
                canonical_name: alias,
                ...
            }
        }

    Args:
        host (str): IP address of the Unbound DNS server. Default is localhost.
        file (str): Path to a file containing the Unbound DNS cache. Default is None.
                    If specified, the function reads the cache from the file instead of the server.
    Returns:
        dict: Dictionary containing the DNS table read from the cache.
    """
    return update_dns_table({}, host, file)
