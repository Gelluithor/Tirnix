#!/bin/sh
# Synthetic workload for the README demo (docs/demo/demo.tape). Everything
# runs inside the throwaway recording container; names say what they are.

# CPU: one busy loop per CPU at the lowest priority, so the terminal
# recorder still gets CPU time when it needs it.
cp /bin/sh /tmp/cpu-burn
for _ in $(seq "$(nproc)"); do
    nice -n 19 /tmp/cpu-burn -c 'while :; do :; done' &
done

# Disk: periodic direct writes so the disk panels show activity.
cp /bin/sh /tmp/disk-writer
/tmp/disk-writer -c 'while :; do dd if=/dev/zero of=/tmp/blob bs=1M count=40 oflag=direct status=none; sleep 0.3; done' &

# A nearly full filesystem (the container gets a 32 MiB tmpfs at /data).
head -c 32600000 /dev/zero > /data/huge.log

# 30 zombies: the parent forks children that exit and never reaps them.
perl -e 'for (1..30) { exit 0 unless fork } sleep 600' &
