--- New Topology ---

192.168.100.254
|
|
|
192.168.100.1 ------ 192.168.100.2 ------ 192.168.100.3
hagent               pmagent1             pmagent2
192.168.101.1        0.0.0.0              0.0.0.0
|                    |                    |
|                    |                    |
|                    |                    |
  192.168.101.3
  mnode
|
|
|
  192.168.101.2
  hnode

--- Hosts ---

1. Scenario 1, mn switch home <-> pma1, cn is host

hagent, pmagent1, mnode

2. Scenario 2, mn switch home <-> pma1, cn is hnode

hagent, pmagent1, mnode, hnode

3. Scenario 3, mn switch pma1 <-> pma2, cn is host

hagent, pmagent1, pmagent2, mnode

4. Scenario 4, mn switch pma1 <-> pma2, cn is hnode

hagent, pmagent1, pmagent2, mnode, hnode

--- By Bridge ---

xenbr0
hagent, pmagent1, pmagent2

xenbr1
hagent, mnode, hnode

xenbr2
pmagent1

xenbr3
pmagent2

--- By Host ---

hagent
 eth0 192.168.100.1 xenbr0
 eth1 192.168.101.1 xenbr1

pmagent1
 eth0 192.168.100.2 xenbr0
 eth1 0.0.0.0 xenbr2

pmagent2
 eth0 192.168.100.3 xenbr0
 eth1 0.0.0.0 xenbr3

hnode
 eth0 192.168.101.2 xenbr1

mnode
 eth0 192.168.101.3 xenbr1

--- Old to New Host Mapping ---
hrouter -> hagent
hagent -> hnode
frouter -> pmagent1
pmagent -> pmagent2

--- Old Topology ---   
 
                      192.168.103.1 ------  192.168.103.2  ------  192.168.103.3
104.254 ------  104.1 crouter               hrouter                frouter
                      192.168.102.1         192.168.100.1          192.168.101.1
                      |                     |                      |
                      |                     |                      |
                      |                     |                      |
                      192.168.102.2         192.168.100.2          192.168.101.2  ------  192.168.100.3
                      cnode                 hagent                 pmagent                mnode

xen-create-image --hostname crouter --ip 192.168.102.1 --netmask 255.255.255.0 --gateway 192.168.100.1
xen-create-image --hostname cnode --ip 192.168.102.2 --netmask 255.255.255.0 --gateway 192.168.102.1
xen-create-image --hostname mnode --ip 192.168.100.3 --netmask 255.255.255.0 --gateway 192.168.100.1
xen-create-image --hostname hrouter --ip 192.168.100.1 --netmask 255.255.255.0
xen-create-image --hostname hagent --ip 192.168.100.2 --netmask 255.255.255.0 -gateway 192.168.100.1
xen-create-image --hostname frouter --ip 192.168.101.1 --netmask 255.255.255.0 -gateway 192.168.100.1
xen-create-image --hostname pmagent --ip 192.168.101.2 --netmask 255.255.255.0 -gateway 192.168.101.1

--- by bridge ---
xenbr0
 hrouter 192.168.100.1
 hagent  192.168.100.2
 mnode   192.168.100.3

xenbr1
 frouter 192.168.101.1
 pmagent 192.168.101.2

xenbr2
 crouter 192.168.102.1
 cnode   192.168.102.2

xenbr3
 crouter 192.168.103.1
 hrouter 192.168.103.2arp -n -Ds 192.168.100.3 eth0 pub
 frouter 192.168.103.3

xenbr5
 pmagent 0.0.0.0
 mnode   192.168.100.3

xenbr4
 crouter 192.168.104.1
 galileo 1192.168.104.254

--- by hosts ---

crouter
 eth0 192.168.102.1 -- xenbr2
 eth1 192.168.103.1 -- xenbr3
 eth2 192.168.104.1 -- xenbr4

cnode
 eth0 192.168.102.2 -- xenbr2

hrouter
 eth0 192.168.103.2 -- xenbr3
 eth1 192.168.100.1 -- xenbr0

frouter
 eth0 192.168.103.3 -- xenbr3
 eth1 192.168.101.1 -- xenbr1

hagent 
 eth0 192.168.100.2 -- xenbr0

pmagent
 eth0 192.168.101.2 -- xenbr1
 eth1 0.0.0.0       -- xenbr5

mnode
 eth0 192.168.100.3 -- xenbr5/xenbr0

--- hagent start mn ---

param
  in: HA
  in: HOA
  in: COA
  in: IF, home link if
  in: TIF, tunnel if name

per PMA
ip tunnel add TIF mode ipip remote COA local HA
ifconfig TIF 0.0.0.0 up

per MN
ip route add HOA/32 dev TIF
arp -n -Ds HOA IF pub

--- hagent stop mn ---

param
  in: HOA
  in: TIF, tunnel if name
  in: IF, home link if

per MN
arp -n -d HOA -i IF pub
ip route del HOA/32 dev TIF

per PMA
ip tunnel del TIF

--- pmagent start mn ---

param
  in: HA
  in: HOA
  in: COA
  in: MIF, mn link if
  in: TIF, tunnel if name
  in: TAB, route table id

per HA
ip tunnel add TIF mode ipip remote HA local COA
ifconfig TIF 0.0.0.0 up
ip route add default dev TIF table TAB

per Link
sysctl -w net.ipv4.conf.MIF.proxy_arp=1

per MN
ip route add HOA/32 dev MIF
ip rule add from HOA/32 lookup TAB


--- pmagent stop mn ---

param
  in: HA
  in: HOA
  in: COA
  in: MIF, mn link if
  in: TIF, tunnel if name
  in: TAB, route table id

per MN
ip route del HOA/32 dev MIF
ip rule del from HOA/32 lookup TAB

per Link
sysctl -w net.ipv4.conf.MIF.proxy_arp=0

per PMA
ip tunnel del TIF
