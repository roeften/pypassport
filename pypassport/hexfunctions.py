# Copyright 2009 Jean-Francois Houzard, Olivier Roger
#
# This file is part of pypassport.
#
# pypassport is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# pypassport is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with pyPassport.
# If not, see <http://www.gnu.org/licenses/>.

#binary to something

def binToHex(val):
    """'\xaa\xbb' --> 4307"""
    return int(binToHexRep(val),16)

def binToHexRep(data):
    """'\xaa\xbb' --> 'aabb'"""
    string= ''
    
    if(type(data) == int):
        return ('%02x' % data).upper()
    
    for x in range(len(data)):         
            if(type(data[x]) == int):
                string += '%02x' % data[x]
            else:
                string += '%02x' % ord(data[x])
    return string.upper()

def binToHexList(data):
    """'\xaa\xbb' --> [0xAA, 0xBB]"""
    return hexRepToList(binToHexRep(data))

#hex to something

def hexToBin(data):
    """511 --> '\x00\x00\x00\x00\x00\x00\x01\xff'"""
    #Si erreur, changer par %x016x%
    return hexRepToBin("%x" % data)

def hexToHexRep(data):
    return hexListToHexRep([data])

def hexToHexList(string):
    # translate string of 2 char HEX to int list
    n= 0
    out= []
    while n < len(string):
        out.append(int(string[n:n+2],16))
        n += 2
    return out

#hexRep to something

def hexRepToBin(string):
    """'AABB' --> \xaa\xbb'"""
    output= b''
    x= 0
    while x < len(string):
            output += struct.pack('B', int(string[x:x + 2],16))
            x += 2
    return output

def hexRepToList(string):
    """'AABBCC' --> [170, 187, 204]"""
    n= 0
    out= []
    while n < len(string):
        out.append(int(string[n:n+2],16))
        n += 2
    return out

def hexRepToHex(string):
    return binToHex(hexRepToBin(string))

def listToHexRep(list):
    """[170, 187, 204] --> 'AABBCC'"""
    out= []
    for item in list:
        out.append('%02X' % (item))
    return out.upper()

#hexList to something    

def hexListToBin(data):
    """[0xAA, 0xBB] -> '\xaa\xbb'"""
    hexRep = hexListToHexRep(data)
    return hexRepToBin(hexRep)

def hexListToHex(data):
    """[0xAA, 0xBB] --> 43707"""
    bin = hexListToBin(data)
    return binToHex(bin)

def hexListToHexRep(data):
    """[0xAA, 0xBB] -> 'AABB4"""
    s= ''
    for d in data:
        x = int(d)	
        s += '%02X' % x
    return s.upper()

def intToBin(data):
    """13 -> d"""
    return hexRepToBin("%x" % int(data))

def intToHexRep(data, size=2):
    """56 -> 38"""
    mask = "%0"+str(size)+"x"
    return (mask % data).upper()

def intToHexList(data):
    return binToHexList(intToBin(data))
    
import struct

def rawbytes(s):
    return s
    """Convert a string to raw bytes without encoding"""
    outlist = []
    for cp in s:
        if(type(cp) == int):
            num = cp
        else:
            num = ord(cp)
        if num < 255:
            outlist.append(struct.pack('B', num))
        elif num < 65535:
            outlist.append(struct.pack('>H', num))
        else:
            b = (num & 0xFF0000) >> 16
            H = num & 0xFFFF
            outlist.append(struct.pack('>bH', b, H))
    return b''.join(outlist)  