from dns_unbound_cache_reader import read_unbound_cache

remote_host = "linksys-router"
dns_cache = read_unbound_cache(remote_host)
print(dns_cache[0])
