#!/bin/bash
# signet run: 1 host (wallet 1 funds) + 3 members + 1 refusing member, real chain view
B=/root/gz/attempt/build/program/s1/gazpacho-slice1
R=/root/gz/attempt/runs/signet-$(date +%m%d-%H%M%S); mkdir -p $R; cd $R
echo $R > /root/gz/attempt/runs/LATEST
nohup $B --role host --dir $R/host --listen 0 --phrase-in /root/gz/secrets/signet-host-1.phrase --change-index 1 --gate $R/GO > host.log 2>&1 &
echo $! > host.pid
for i in $(seq 1 300); do [ -f $R/host/invite ] && break; grep -q FATAL host.log && exit 1; sleep 1; done
read ADDR SCOPE < $R/host/invite
nohup $B --role member --dir $R/bad --join $ADDR --scope $SCOPE --bad-conditions > bad.log 2>&1 &
echo $! > bad.pid
for m in 1 2 3; do nohup $B --role member --dir $R/m$m --join $ADDR --scope $SCOPE > m$m.log 2>&1 & echo $! > m$m.pid; sleep 2; done
