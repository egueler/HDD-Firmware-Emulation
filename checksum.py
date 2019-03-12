#!/usr/bin/python

import sys

checksum = 0
i = 0
for b in open(sys.argv[1]).read():
  checksum += ord(b)
  checksum = checksum & 0xff
  print "pos %d (byte %02x): %s" % (i, ord(b), hex(checksum))
  i += 1 
print hex(checksum)
