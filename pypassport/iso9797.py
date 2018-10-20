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

from Crypto.Cipher import DES
from pypassport.hexfunctions import *

def pad(toPad):
    size = 8
    padBlock = "\x80" +  "\x00"*7
    left = size - (len(toPad) % size)
    return toPad + padBlock[0:left]

def unpad(tounpad):
    i=-1
    while tounpad[i] == "\x00":
        i -= 1
        
    if tounpad[i] == "\x80":
        return tounpad[0:i]
    else:
        #Pas de padding
        return tounpad
        

def mac(key, msg):
        #Source: PKI for machine readable travel document offering
        #        ICC read-only access
        #Release:1.1
        #October 01,2004
        #p46 of 57
        
#        print 'MAC'
#        print '---'
        
        size = len(msg) / 8
        y = '\x00'*8
        tdesa = DES.new(key[0:8], DES.MODE_CBC, y)
#        print 'IV: ' + binToHexRep(y)
        
        for i in range(size):
#            print 'x' + str(i) + ': ' + binToHexRep(msg[i*8:i*8+8])
            y = tdesa.encrypt(msg[i*8:i*8+8])
#            print 'y' + str(i) + ': ' + binToHexRep(y)
            
        tdesb = DES.new(key[8:16])
        tdesa = DES.new(key[0:8])
        
        b = tdesb.decrypt(y)
#        print 'b: ' + binToHexRep(b)
        a = tdesa.encrypt(b)
#        print 'a: ' + binToHexRep(a)
        
        return a
