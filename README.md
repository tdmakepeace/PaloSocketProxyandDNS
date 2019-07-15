# PaloSocketProxyandDNS
Palo Alto Networks - Tool for helping to support the bootstrap process of a VM-Series without direct internet access from the 
management interface.
<br><br>
The tool acts as a DNS server on the management networks, and returns the addresses configured for the main sites the Palo Alto Networks 
NGFW needs during the bootstrapping process.<br>
The tool also creates socket proxies on those addresses through to the real desitinations.<br>
The idea behind it, is to act as a proxy server to give the NGFW access to the Palo Alto Networks sites over the internet from a walled-garden networks.
<br>
	

# To setup
On a host configure secondary IP-addresses on the interface to be used as the socket-proxy. <br> <br>
Configure the NGFW to use the default address as the default-gateway and the DNS server.<br>

<br>
As long as the host running the script has access to the internet via a true proxy or secondary interface the only sites the NGFW will have access to are defined in the script.

# Disclaimer
This software is provided without support, warranty, or guarantee. Use at your own risk.
