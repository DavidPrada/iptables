#!/bin/bash
#▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
# Firewall configuration using iptables
#▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬
# 	netstat -puntal
# 	sudo iptables -S
# 	sudo iptables -L --line-numbers
#		sudo iptables -D INPUT -j DROP
#		sudo invoke-rc.d iptables-persistent save

# IPv4
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F

# Current State
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
sudo iptables -A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -o eth0 -p tcp --sport 22 -j ACCEPT

# SublimeText3 Remote Edit
sudo iptables -A INPUT -p tcp -s 127.0.0.1 --dport 55555 -j ACCEPT

# Unlimited lo access
sudo iptables -I INPUT 1 -i lo -j ACCEPT
sudo iptables -I OUTPUT 1 -o lo -j ACCEPT

# Drop sync
sudo iptables -A INPUT -i eth0 -p tcp ! --syn -m state --state NEW -j DROP

# Drop Fragments
sudo iptables -A INPUT -i eth0 -f -j DROP
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j DROP

# Drop NULL packets
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " NULL Packets "
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Drop XMAS
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " XMAS Packets "
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Drop FIN packet scans
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " Fin Packets Scan "
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags FIN,ACK FIN -j DROP
sudo iptables  -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Log and get rid of broadcast / multicast and invalid 
sudo iptables  -A INPUT -i eth0 -m pkttype --pkt-type broadcast -j LOG --log-prefix " Broadcast "
sudo iptables  -A INPUT -i eth0 -m pkttype --pkt-type broadcast -j DROP
 
sudo iptables  -A INPUT -i eth0 -m pkttype --pkt-type multicast -j LOG --log-prefix " Multicast "
sudo iptables  -A INPUT -i eth0 -m pkttype --pkt-type multicast -j DROP
 
sudo iptables  -A INPUT -i eth0 -m state --state INVALID -j LOG --log-prefix " Invalid "
sudo iptables  -A INPUT -i eth0 -m state --state INVALID -j DROP

# Allow incoming ICMP ping pong stuff
sudo iptables -A INPUT -i eth0 -p icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED,RELATED -m limit --limit 30/sec  -j ACCEPT
sudo iptables -A OUTPUT -o eth0 -p icmp --icmp-type 0 -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow incoming HTTP port 80
sudo iptables -A INPUT -i eth0 -p tcp -s 0/0 --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -o eth0 -p tcp --sport 80 -d 0/0 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

# Allow outgoing NTP
# sudo iptables -A OUTPUT -o eth0 -p udp --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT
# sudo iptables -A INPUT -i eth0 -p udp --sport 123 -m state --state ESTABLISHED -j ACCEPT
 
# Allow outgoing SMPT
# sudo iptables -A OUTPUT -o eth0 -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
# sudo iptables -A INPUT -i eth0 -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

# drop and log everything else
sudo iptables -A INPUT -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix " DEFAULT DROP "
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -j DROP

# Block all IPV6
sudo ip6tables -P INPUT DROP
sudo ip6tables -P OUTPUT DROP
sudo ip6tables -P FORWARD DROP

# Reload this iptable rules after server reboot
sudo apt-get update
sudo apt-get install -y iptables-persistent