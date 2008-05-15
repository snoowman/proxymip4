#/bin/sh
ssh hagent /etc/init.d/pmip4-ha $@
ssh pmagent1 /etc/init.d/pmip4-pma $@
ssh pmagent2 /etc/init.d/pmip4-pma $@
