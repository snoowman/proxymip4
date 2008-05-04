#!/bin/sh
echo ==== ip link \| grep mit ====
ip link | grep mit
echo ==== ip tunnel -n ====
ip tunnel
echo ==== ip route -n ====
ip route
echo ==== ip rule -n ====
ip rule
echo ==== arp -n ====
arp -n 2> /dev/null
echo ==== sysctl -a \| grep proxy_arp ====
sysctl -a 2> /dev/null | grep proxy_arp

