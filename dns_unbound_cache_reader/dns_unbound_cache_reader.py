import subprocess
from fabric import Connection, Config


## Global variables
localhost = [
    "localhost",
    "127.0.0.1"
]
cmd = "unbound-control dump_cache"


def read_unbound_cache(host: str = "127.0.0.1"):
    """
    Read the Unbound DNS cache and return it as a dictionary.

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
        result = remote.run(cmd)
        dns_cache = result.stdout.strip().split("\n")
    

    return dns_cache
