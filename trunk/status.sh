#!/bin/sh
echo ==== ip tunnel -n ====
ip tunnel
echo ==== ip route -n ====
ip route
echo ==== ip rule -n ====
ip rule
echo ==== arp -n ====
arp -n
