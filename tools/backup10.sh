#!/bin/sh
cd /home/one/chrony-rs
rm -f /home/one/chrony-rs-testing10.zip
find . -not -path './target/*' -not -path './.git/*' -not -name '.' -not -name '.git' -not -name 'target' | zip -r@ /home/one/chrony-rs-testing10.zip
echo "DONE"
ls -lh /home/one/chrony-rs-testing10.zip
