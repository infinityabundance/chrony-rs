#!/bin/sh
cd /home/one/chrony-rs
rm -f /home/one/chrony-rs-testing9.zip
find . -not -path './target/*' -not -path './.git/*' -not -path '.' -not -path './.git' -not -path './target' | zip -r@ /home/one/chrony-rs-testing9.zip
echo "Zip created: $(ls -lh /home/one/chrony-rs-testing9.zip | awk '{print $5}')"
