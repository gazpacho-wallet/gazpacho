#!/bin/bash
# loopback run: 1 host + 3 good members + 1 refusing member, fake chain
B=/root/gz/attempt/build/program/s1/gazpacho-slice1
R=/root/gz/attempt/runs/loop-$(date +%H%M%S); mkdir -p $R; cd $R
TIP=300000
$B --role host --dir $R/host --listen 0 --fake-chain --fake-tip $TIP > host.log 2>&1 &
HP=$!
for i in $(seq 1 50); do [ -f $R/host/invite ] && break; sleep 0.2; done
read ADDR SCOPE < $R/host/invite
$B --role member --dir $R/bad --join $ADDR --scope $SCOPE --bad-conditions --fake-chain --fake-tip $TIP > bad.log 2>&1 &
for m in 1 2 3; do $B --role member --dir $R/m$m --join $ADDR --scope $SCOPE --fake-chain --fake-tip $TIP > m$m.log 2>&1 & done
for i in $(seq 1 ${WAIT:-90}); do grep -q "factory active\|FATAL\|signing-failed" host.log && break; sleep 1; done
sleep 3
kill $(jobs -p) 2>/dev/null; wait 2>/dev/null
echo "run dir $R"
for f in host m1 m2 m3 bad; do echo "===== $f"; grep -v "chain:   \|^$" $f.log | head -${LINES_PER:-60}; done
