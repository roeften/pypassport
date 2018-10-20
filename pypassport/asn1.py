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
from pyasn1.type.univ import *
from pyasn1.type.namedtype import *
from pyasn1.type.namedval import *
from pyasn1.type.constraint import *
from pyasn1.codec.der import encoder 

class asn1Exception(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

def asn1Length(data):
    """
    Take an asn.1 length, and return a couple with the decoded length in hexa and the total length of the encoding (1,2 or 3 bytes)

    >>> from pyPassport.asn1.asn1 import *
    >>> asn1Length("\x22")
    (34, 1)
    >>> asn1Length("\x81\xaa")
    (170, 2)
    >>> asn1Length("\x82\xaa\xbb")
    (43707, 3)
    
    @param data: A length value encoded in the asn.1 format.
    @type data: A binary string.
    @return: A tuple with the decoded hexa length and the length of the asn.1 encoded value.
    @raise asn1Exception: If the parameter does not follow the asn.1 notation.

    """
    if data[0] <= "\x7F":
        return (binToHex(data[0]), 1)
    if data[0] == "\x81":
        return (binToHex(data[1]), 2)
    if data[0] == "\x82":
        return (binToHex(data[1:3]), 3)
    
    raise asn1Exception("Cannot decode the asn1 length from this field: " + binToHexRep(data))

def toAsn1Length(data):
    """  
    Take an hexa value and return the value encoded in the asn.1 format.
    
    >>> binToHexRep(toAsn1Length(34))
    '22'
    >>> binToHexRep(toAsn1Length(170))
    '81aa'
    >>> binToHexRep(toAsn1Length(43707))
    '82aabb'
    
    @param data: The value to encode in asn.1
    @type data: An integer (hexa)
    @return: The asn.1 encoded value
    @rtype: A binary string
    @raise asn1Exception: If the parameter is too big, must be >= 0 and <= FFFF
    """
    if data <= binToHex("\x7F"):
        return hexToBin(data)
    if data >= binToHex("\x80") and data <= binToHex("\xFF"):
        return "\x81" + hexRepToBin( "%02x" % data)
    if data >= binToHex("\x01\x00") and data <= binToHex("\xFF\xFF"):
        return "\x82" + hexRepToBin("%04x" % data)
    
    raise asn1Exception("The value is too big, must be <= FFFF")


class AlgorithmIdentifier(Sequence): 
    componentType = NamedTypes( 
        NamedType('algorithm', ObjectIdentifier()), 
        OptionalNamedType('parameters', Null()) 
        ) 

ub_DataGroups = Integer(16)

id_icao = ObjectIdentifier((2,23,136))
id_icao_mrtd = ObjectIdentifier(id_icao + (1,))
id_icao_mrtdsecurity = ObjectIdentifier(id_icao_mrtd + (1,))
id_icao_ldsSecurityObject = ObjectIdentifier(id_icao_mrtdsecurity + (1,))

DigestAlgorithmIdentifier = AlgorithmIdentifier()

class LDSSecurityObjectVersion(Integer):
    namedValues = NamedValues(
        ('V0', 0)
        )
 
class DataGroupNumber(Integer):
    namedValues = NamedValues(
        ('dataGroup1', 1),
        ('dataGroup2', 2),
        ('dataGroup3', 3),
        ('dataGroup4', 4),
        ('dataGroup5', 5),
        ('dataGroup6', 6),
        ('dataGroup7', 7),
        ('dataGroup8', 8),
        ('dataGroup9', 9),
        ('dataGroup10', 10),
        ('dataGroup11', 11),
        ('dataGroup12', 12),
        ('dataGroup13', 13),
        ('dataGroup14', 14),
        ('dataGroup15', 15),
        ('dataGroup16', 16)
        )
    
       
class DataGroupHash(Sequence):
    componentType=NamedTypes( 
        NamedType('dataGroupNumber', Integer()), 
        NamedType('dataGroupHashValue', OctetString()) 
        )

class DataGroupHashValues(SequenceOf):
    componentType = DataGroupHash()    
    subtypeSpec = ValueSizeConstraint(2, ub_DataGroups)

class LDSSecurityObject(Sequence):
    componentType=NamedTypes( 
        NamedType('version', LDSSecurityObjectVersion()),
        NamedType('hashAlgorithm', DigestAlgorithmIdentifier), 
        NamedType('dataGroupHashValues', DataGroupHashValues()) 
    )
    
class SubjectPublicKeyInfo(Sequence):
    componentType = NamedTypes( NamedType('algorithm', AlgorithmIdentifier()), 
                                          NamedType('subjectPublicKey', BitString())
                                          )