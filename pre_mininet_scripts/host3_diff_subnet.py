py "Configuring network"
h1 ifconfig h1-eth0 10.0.1.1/24
h2 ifconfig h2-eth0 10.0.2.1/24
h3 ifconfig h3-eth0 10.0.3.1/24
h1 route add default gw 10.0.1.1
h2 route add default gw 10.0.2.1
h3 route add default gw 10.0.3.1
