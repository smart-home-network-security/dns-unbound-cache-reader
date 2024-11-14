# Libraries
import os
# Package under test
import dns_unbound_cache_reader as dns_reader
from dns_unbound_cache_reader import DnsTableKeys


# Variables
self_path = os.path.abspath(__file__)
self_dir = os.path.dirname(self_path)
sample_cache_file = os.path.join(self_dir, "sample_dns_cache.txt")


### TEST FUNCTIONS ###

def test_read_sample_cache_file() -> None:
    """
    Test reading a sample cache file.
    """
    dns_table = dns_reader.read_dns_cache(file=sample_cache_file)
    assert DnsTableKeys.IP.name in dns_table
    assert DnsTableKeys.ALIAS.name in dns_table

    dns_table_ip = dns_table[DnsTableKeys.IP.name]
    assert len(dns_table_ip) == 6
    assert dns_table_ip["93.184.216.34"] == "example.com"
    assert dns_table_ip["2606:2800:220:1:248:1893:25c8:1946"] == "example.com"
    assert dns_table_ip["192.0.2.1"] == "ns1.example.org"
    assert dns_table_ip["198.51.100.1"] == "ns2.example.org"
    assert dns_table_ip["192.0.2.2"] == "example.com"
    assert dns_table_ip["192.168.1.100"] == "example.local"
    
    dns_table_alias = dns_table[DnsTableKeys.ALIAS.name]
    assert len(dns_table_alias) == 3
    assert dns_table_alias["example1.local"] == "example.local"
    assert dns_table_alias["server1.example.com"] == "_tcp_.matter.example.com"
    assert dns_table_alias["server2.example.com"] == "_tcp_.matter.example.com"
