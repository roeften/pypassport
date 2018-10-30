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

from pypassport.hexfunctions import *
from pypassport.asn1 import asn1Exception, asn1Length

class TLVParserException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class TLVParser(dict):
    def __init__(self, data):
        self._data = data
        self._byteNb = 0
        
    def _getTag(self):
        raise Exception("Should be implemented")
    
    def _getLength(self):     
        (length, offset) = asn1Length(self._data[self._byteNb:])
        self._byteNb += offset
        return length
    
    def _getValue(self):
        length = self._getLength()
        value = self._data[self._byteNb:self._byteNb+length]
        self._byteNb += length
        return value
    
    def parse(self):
        self._byteNb = 0
        self.clear()
        try:
            while self._byteNb < len(self._data)-1:
                tag = self._getTag()
                value = self._getValue()
                self[tag] = value
                
        except asn1Exception as exc:
            raise TLVParserException(exc[0])
            
        return self
    
        
        