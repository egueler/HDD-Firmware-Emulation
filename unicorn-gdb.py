#!/usr/bin/python
# Emulating SAMSUNG HM641JI HDD firmware.

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import sys, copy, binascii, json
import datetime
import time, os
from capstone import *
from capstone.arm import *
import signal

# memory address where emulation starts
ADDRESS = 0xfff00000
STACK_ADDRESS = 0x80000000
STACK_SIZE = 0x10000

srcAddr = 0x0
srcLen = 0x0
dstAddr = 0x0

lastAddr = 0x0

lastTime = time.time()
lastLR = 0x0
foundFunctions = []
md = None

def unpackAddress(address, littleEndian=True):
    newAddress = copy.copy(address)
    if littleEndian:
      # reverse byte order
      for counter in range(0, len(address)):
        newAddress[counter] = address[len(address)-counter-1]
    return int(binascii.hexlify(newAddress), 16)

def printHexDump(buf, len):
    for i in range(len):
        if i % 16 == 0:
            sys.stdout.write("\n")
            sys.stdout.write("%08x: " % (buf + i))
        sys.stdout.write("%02x " % mu.mem_read(buf + i, 1)[0])
    sys.stdout.write("\n")

def hookReadMemory(mu, access, address, size, value, user_data):
    value = unpackAddress(mu.mem_read(address, size))
    print("hookReadMemory(-, %08x, %08x, %x, %x, -)" % (access, address, size, value))
    return True

def hookWriteMemory(mu, access, address, size, value, user_data):
    print("hookWriteMemory(-, %08x, %08x, %x, %x, -)" % (access, address, size, value))
    return True

def hookInvalidMemory(mu, access, address, size, value, user_data):
    generateDump()
    dumpFoundFunctions()
    print("hookInvalidMemory(-, %08x, %08x, %x, %x, -)" % (access, address, size, value))
    return True

def hookInvalidFetchMemory(mu, access, address, size, value, user_data):
    print("hookInvalidFetchMemory(-, %08x, %08x, %x, %x, -)" % (access, address, size, value))
    return True

def getDisassembly(code, addr=0x0):
    global md, mu
    disassembly = ""
    if mu.query(UC_QUERY_MODE) == UC_MODE_LITTLE_ENDIAN:
        md.mode = CS_MODE_LITTLE_ENDIAN
    else:
        md.mode = CS_MODE_THUMB
    for x in md.disasm(code, addr):
        disassembly += "%s %s\n" % (x.mnemonic, x.op_str)
    return disassembly[:-1]

def generateDump():
    global mu
    now = datetime.datetime.now().isoformat()
    os.system("mkdir dumps/%s" % now)
    for (map_start, map_end, map_perms) in mu.mem_regions():
        open('dumps/%s/rom-%x.bin' % (now, map_start), "w+").write(mu.mem_read(map_start, map_end - map_start))
    # create dump containing ALL
    '''f = open('dumps/%s/ALL.bin' % (now), "w+")
    first = True
    lastMapEnd = 0x0
    f.write("\x00" * (2**32))
    for (map_start, map_end, map_perms) in sorted(mu.mem_regions(), key=lambda x: x[0]):
        #if(map_start - lastMapEnd - 1 > 0):
        #    f.write("\x00" * (map_start - lastMapEnd - 1))
        f.seek(map_start)
        f.write(mu.mem_read(map_start, map_end - map_start))
        lastMapEnd = map_end
    f.close()'''

def hookCode(mu, address, size, user_data):
    global ADDRESS, buf, srcAddr, dstAddr, srcLen, lastAddr, lastTime, foundFunctions, lastLR
    if(time.time() - lastTime > 3):
        print("Status update, i'm here: %08x" % address) 
        lastTime = time.time()
        for i in range(13):
            sys.stdout.write("R%d: %x, " % (i, mu.reg_read(eval("UC_ARM_REG_R%d" % i))))
        sys.stdout.write("SP: %x" % mu.reg_read(UC_ARM_REG_SP))
        sys.stdout.write("\n")
    print("%08x: %s" % (address, getDisassembly(mu.mem_read(address, size), address)))


    currentLR = mu.reg_read(UC_ARM_REG_LR)
    if currentLR != lastLR:
        print("LR changed, probably function called: %08x (thumb=%d)" % (address, int(mu.query(UC_QUERY_MODE) == UC_MODE_THUMB)))
        foundAddress = address
        if address > ADDRESS:
            foundAddress -= ADDRESS
        foundFunctions.append((foundAddress, int(mu.query(UC_QUERY_MODE) == UC_MODE_THUMB)))
        lastLR = currentLR
    #print("%08x" % address)
    #if max(lastAddr, address) - min(lastAddr, address) > 0x50:
    #    print("Possible new function: %x" % address)
    if address == ADDRESS+0x0000194:
        print("loading unpack loader ERROR")
        mu.emu_stop()
    elif address == ADDRESS+0x1A0:
        print("loading unpack loader successful")
        printHexDump(0x159F0, 0x100)
        #mu.emu_stop()
    elif address == 0x15C8C:
        print("chksum err\n")
    elif address == 0x15CBC:
        print("decomp err\n")

    if address == ADDRESS+0x3A2 or address == 0x3A2:
        print("decompress called\n")

    if address == ADDRESS+0x1A4:
        mu.reg_write(UC_ARM_REG_PC, 0x159F0)

    if address == ADDRESS+0x664 or address == 0x10664:
        srcAddr = mu.reg_read(UC_ARM_REG_R0)
        dstAddr = mu.reg_read(UC_ARM_REG_R1)
        srcLen = mu.reg_read(UC_ARM_REG_R2)
        print("%08x calling __copy(dst=%x, src=%x, len=%x, a4=%x)" % (address, srcAddr, dstAddr, srcLen, mu.reg_read(UC_ARM_REG_R3)))
        mu.reg_write(UC_ARM_REG_R3, 0x1)
    if address == ADDRESS+0x704 or address == 0x10704:
        print("__copy finished") #, buffer was: %s" % [hex(x) for x in buf])
        #printHexDump(srcAddr, srcLen)
        printHexDump(dstAddr, srcLen)
    
    #if address == 0x10686:
    #    #printHexDump(0x10686, 0x100)
    #    #generateDump()
    #    #mu.emu_stop()
    #    mu.mem_write(0x1c00a204, "\x00\x00\x00\x00")

    if address == ADDRESS+0x3A2:
        print("decompressing started")
        mu.emu_stop()

    if address == 0x1068C:
        value = ("%08x" % (mu.reg_read(UC_ARM_REG_R1)-mu.reg_read(UC_ARM_REG_R2)-1)).decode("hex")[::-1]
        #print("Setting 0x1c00A204 to %08x (%s), R0=%08x, R1=%08x, R2=%08x" % (mu.reg_read(UC_ARM_REG_R1)-mu.reg_read(UC_ARM_REG_R2)-1, value.encode("hex"), mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1), mu.reg_read(UC_ARM_REG_R2)))
        mu.mem_write(0x1c00a204, value)

    if address == 0xEDC6:
        mu.reg_write(UC_ARM_REG_R0, mu.reg_read(UC_ARM_REG_R4))

    if address == 0x15D34:
        mu.mem_write(0xFFFE005C, "\x01\x40\x00\x00")
    elif address == 0x15DDC:
        mu.mem_write(0xFFFE005C, "\x02\x40\x00\x00")
    # function to output byte to console or something, 
    # waits for device to react, which of course never happens in simulation
    # so just exit the function
    #if address == ADDRESS+0x1E4:
    #    mu.reg_write(UC_ARM_REG_PC, ADDRESS+0x1F2)
    
    #print("a4: %x" % unpackAddress(mu.mem_read(0x7fffffb8, 4)))
    #if address in [ADDRESS+x for x in [0x678, 0x684, 0x68A, 0x690, 0x696, 0x69C]]:
    #    #print("byte: %02x" % mu.reg_read(UC_ARM_REG_R5))
    #    buf.append(mu.reg_read(UC_ARM_REG_R5))
    #if address in [ADDRESS+x for x in [0x67E, 0x6a4]]:
    #    #print("byte: %02x" % mu.reg_read(UC_ARM_REG_R0))
    #    buf.append(mu.reg_read(UC_ARM_REG_R5))
    
    if address == 0x73C0:
        mu.mem_write(0x400385c, "\x02\x00\x00\x00")

    lastAddr = address
    pass

def dumpFoundFunctions():
    global foundFunctions
    print(["%08x (thumb=%d)" % (x, y) for (x, y) in list(set(foundFunctions))])
    open("foundFuncs.json", "w+").write(json.dumps(list(set(foundFunctions))))

def signal_handler(sig, frame):
    global foundFunctions
    print('You pressed Ctrl+C!')
    generateDump()
    dumpFoundFunctions()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

md = Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN)
md.detail = True
print("Emulate ARM code")
# Initialize emulator in X86-32bit mode
mu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)

# read rom file
filename = 'rom.bin'

#for now hardcoded filename!, uncomment next line if you want to get filename from user input.
#filename = sys.argv[1]

f = open(filename, "r")
content = f.read()



# map 2MB memory for this emulation
mu.mem_map(ADDRESS, len(content)) # code
mu.mem_map(STACK_ADDRESS-STACK_SIZE, STACK_SIZE) # stack
mu.mem_map(0x1C000000, 0x1000000) # On this CPU the 0x1C00A000 - 0x1C00AFFF range appears to be mapped to various ports and test pads all around the PCB.
#mu.mem_map(0x4005800, 0x100000) # no idea (0x4005B60)
mu.mem_map(0x14000, 0x100000) # sub_81E,  0x148E0
mu.mem_map(0x0, 0x14000)
mu.mem_map(0x4000000, 0x8000)
mu.mem_map(0x18000000, 0x1000000)
mu.mem_map(0xfffe0000, 0x10000)
mu.mem_map(0x10000000, 0x1000000)
mu.mem_map(0x43080000, 0x1000000)
#mu.mem_map(0x4800, 0x1000)

mu.mem_write(0x1C00A000+0xA0, "\x1E") # fix for 0x906 - 0x90C
mu.mem_write(0x1C00A000+0x62C, "\xff") # fix for 0x1e6 - 0x1ec
#mu.mem_write(0x1C00A000+0xC58, "\xff") # fix for 0x1e6 - 0x1ec 

# __copy needs to have a4 = 1 to activate block-copy (and not the weird memory[0x...] shit)
mu.mem_write(0x7fffffb8, "\x01\x00\x00\x00") # stack #0x48+var_48 = 1
# but a4 will be overwritten by sub_81E unless these values are set
#mu.mem_write(0x4005B60, "\x01\x00\x00\x00") 
mu.mem_write(0x4005B60, "\x3A\x7C\x37\x54")

mu.mem_write(0x1C004A0C, "\x01\x00\x00\x00")

#mu.mem_write(0x4005B64, "\x00\xF6\x05\x00")
mu.mem_write(0x4005B64, "\x00\xF6\xEF\xFF")

mu.mem_write(0x1C002E14, "\xff\xff\xff\xff")

mu.mem_write(0xFFFE005C, "\x01\x40\x00\x00")
mu.mem_write(0xFFFE005C, "\x02\x40\x00\x00")
#print("a4: %x" % unpackAddress(mu.mem_read(0x7fffffb8, 4)))

# write machine code to be emulated to memory
mu.mem_write(ADDRESS, content)

# initialize machine registers
#mu.reg_write(UC_X86_REG_ECX, 0x1234)
#mu.reg_write(UC_X86_REG_EDX, 0x7890)
mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)

# hooks
hook_mem_read       = mu.hook_add(UC_HOOK_MEM_READ, hookReadMemory, None)
hook_mem_write      = mu.hook_add(UC_HOOK_MEM_WRITE, hookWriteMemory, None)
hook_mem_read_unm   = mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED, hookInvalidMemory, None)
hook_mem_fetch      = mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED|UC_HOOK_MEM_FETCH_PROT|UC_HOOK_MEM_FETCH_INVALID, hookInvalidFetchMemory, None)
hook_code           = mu.hook_add(UC_HOOK_CODE, hookCode, None)

# emulate code in infinite time & unlimited instructions
mu.emu_start(ADDRESS+0x10, -1)
#now = datetime.datetime.now()
#open('dumps/rom-%s.bin' % (now.isoformat()), "w+").write(mu.mem_read(ADDRESS, len(content)))



# now print out some registers
print("Emulation done.")
dumpFoundFunctions()
#r_ecx = mu.reg_read(UC_ARM_REG_ECX)
#r_edx = mu.reg_read(UC_ARM_REG_EDX)
#print(">>> ECX = 0x%x" %r_ecx)
#print(">>> EDX = 0x%x" %r_edx)
