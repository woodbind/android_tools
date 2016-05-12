#!/usr/bin/python -E

import os
import re
import sys

def PrintUsage():
    print "Usage:" + sys.argv[0] + " vmlinux dumpfile"
    print "    vmlinux : kernel with symbol"
    print "    dumpfile: sysdump file with ELF header"

if (len(sys.argv) <= 2 or len(sys.argv) > 3):
    PrintUsage()
    sys.exit(1)

vmlinux = sys.argv[1]
dumpfile = sys.argv[2]

# get the offset & size of .text section from vmlinux
stream = os.popen("readelf -W -S %s | grep '\s\.text'" % vmlinux)
for line in stream:
    textline = re.split('\s\s+', line.strip())[2]
    addrs = re.split('\s',textline.strip())
    sstart = addrs[1].strip()
    ssize = addrs[2].strip()
    sloadaddr = addrs[0].strip()
    print "Found .text section in vmlinux, start:" + sstart + ",size:" + ssize + ",loadaddr:" + sloadaddr
    

if 'line' not in dir():
    print "read %s failure, exiting" % vmlinux
    sys.exit(1)

# get __v7_setup_stack addr if exist
found_v7_setup_stack = 0
stream = os.popen("readelf -W -s %s | grep '__v7_setup_stack'" % vmlinux)
for symline in stream:
    ssym_addr = re.split('\s+', symline.strip())[1]
    ssym_addr = ssym_addr.strip()
    print "Found __v7_setup_stack in vmlinux, addr:" + ssym_addr
    found_v7_setup_stack = 1

if 'symline' not in dir():
    print "__v7_setup_stack not found in %s" % vmlinux

start = int(sstart, 16)
size = int(ssize, 16) + 1
loadaddr = int(sloadaddr[8:], 16)
if found_v7_setup_stack == 1:
    sym_addr = int(ssym_addr[1:], 16)
    stack_addr = (sym_addr - start)/4

size_text_end = size/4
# get rodata section if exist
found_rodata_section = 0
stream = os.popen("readelf -W -S %s | grep '\s\.rodata'" % vmlinux)
for roline in stream:
    textline = re.split('\s\s+', roline.strip())[2]
    addrs = re.split('\s',textline.strip())
    sstart = addrs[1].strip()
    ssize = addrs[2].strip()
    sloadaddr = addrs[0].strip()
    print "Found .rodata section in vmlinux, start:" + sstart + ",size:" + ssize + ",loadaddr:" + sloadaddr
    found_rodata_section = 1
if 'roline' not in dir():
    print "No .rodata found in %s, continue" % vmlinux

# .rodata always follows .text
if found_rodata_section == 1:
    size += int(ssize, 16)

vmlinuxobj = open(vmlinux, 'rb')
dumpobj = open(dumpfile, 'rb')

vmlinuxobj.seek(start, 0)

# read ph to get load offset in dump
stream = os.popen("readelf -W -l %s | grep 'LOAD'" % dumpfile)
for line in stream:
    textline = re.split('\s\s+', line.strip())[1]
    addrs = re.split('\s',textline.strip())
    soffset = addrs[0].strip()
    print "Found LOAD in dumpfile, offset:" + soffset
    break

if 'line' not in dir():
    print "read %s failure, exiting" % dumpfile
    sys.exit(1)

phload = int(soffset, 16)
xxx = loadaddr + phload
print "xxx offset:" + str(xxx)
dumpobj.seek(loadaddr + phload, 0)


tmpvm = open('./tmpvm', 'wb+')
tmpvm.write(vmlinuxobj.read(size))
tmpdump = open('./tmpdump', 'wb+')
tmpdump.write(dumpobj.read(size))


# check verion first
# get linux_banner
stream = os.popen("readelf -W -s %s | grep 'linux_banner'" % vmlinux)
for bannerline in stream:
    banner_addr = re.split('\s+', bannerline.strip())[1]
    banner_addr = banner_addr.strip()
    banner_size = re.split('\s+', bannerline.strip())[2]
    banner_size = banner_size.strip()
    print "Found linux_banner in vmlinux, addr:" + banner_addr + ",size:" + banner_size
    break

if 'bannerline' not in dir():
    print "linux_banner not found in %s" % vmlinux
    sys.exit(1)

banner_offset = int(banner_addr[8:], 16) - loadaddr

tmpvm.seek(banner_offset, 0)
vversion = tmpvm.read(int(banner_size, 10))
print "Linux version in vmlinux :" + vversion

tmpdump.seek(banner_offset, 0)
dversion = tmpdump.read(int(banner_size, 10))
print "Linux version in dumpfile:" + dversion

if dversion != vversion:
    print "%s and %s does not match, exiting" % (vmlinux,dumpfile)
#    sys.exit(1)

stream.close()


vmlinuxobj.close()
dumpobj.close()
tmpvm.close()
tmpdump.close()

# dump into text file
hexarg = "4/1 \"%02X\" \"\\n\""
streamdp = os.popen("hexdump -v -e '%s' tmpdump " % hexarg)
streamvm = os.popen("hexdump -v -e '%s' tmpvm " % hexarg)

# ready to compare
count = 0
diff = 0
diff_text = 0
diff_rodata = 0
while True:
    line1 = streamdp.readline().strip()
    line2 = streamvm.readline().strip()
    count += 1
    if line1 == '' or line2 == '':
        break
    # skip __v7_setup_stack
    if found_v7_setup_stack == 1:
        if (count > stack_addr and count <= (stack_addr+11)):
            continue
    # skip ftrace modified in .text
    if (line1 == '0040BDE8' and line2[6:] == 'EB'):
        continue
    # skip ftrace modified in .rodata
    if (line2 == '00000000'):
        continue
    if line1 != line2:
        diff += 1
        print "diff: in sysdump: %s, in vmlinux: %s" % (line1, line2)
        if count > size_text_end:
            diff_rodata += 1
        else:
            diff_text += 1

print "Found %d diffs. %d in .text and %d .rodata." % (diff, diff_text, diff_rodata)    

streamdp.close()
streamvm.close()
