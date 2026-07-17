#!/bin/sh
cd /home/one/chrony-rs && tar czf /home/one/chrony-rs-testing9.tar.gz --exclude=target --exclude=.git .
echo "Backup complete"
ls -lh /home/one/chrony-rs-testing9.tar.gz
