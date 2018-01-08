onetwopunch
===========

Nmap is by far the most comprehensive port scanner, able to identify services, fingerprint operating systems, and even run several scripts against the services to identify potential vulnerabilities. This helps cut down the manual work involved in service enumeration. Nmap uses a default list of ports when none are provided by the attacker. This can cause nmap to miss certain ports that are not in its default list. There is the option to let nmap scan all 65,535 ports on each machine, but as you can imagine, this will take a considerable amount of time, especially if you’re scanning a lot of targets.

Unicornscan is another port scanner that utilizes it’s own userland TCP/IP stack, which allows it to run a asynchronous scans. This makes it a whole lot faster than nmap and can scan 65,535 ports in a relatively shorter time frame. Since unicornscan is so fast, it makes sense to use it for scanning large networks or a large number of ports.

So, the idea behind this post is to utilize both tools to generate a scan of 65,535 ports on the targets. We will use unicornscan to scan all ports, and make a list of those ports that are open. We will then take the open ports and pass them to nmap for service detection.

For more details, see [http://blog.techorganic.com/2012/05/31/port-scanning-one-two-punch/](http://blog.techorganic.com/2012/05/31/port-scanning-one-two-punch/)
