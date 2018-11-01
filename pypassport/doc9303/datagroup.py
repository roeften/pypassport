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

from pypassport import doc9303
from pypassport.tlvparser import TLVParser, TLVParserException
from pypassport.asn1 import *
from pypassport.hexfunctions import *
from pypassport.logger import Logger
from pypassport.iso19794 import ISO19794_5
from pypassport.iso7816 import Iso7816
from pypassport.doc9303 import converter, mrz, bac
from pypassport.openssl import OpenSSL, OpenSSLException
from pypassport.derobjectidentifier import *
from pypassport.singleton import Singleton
from hashlib import *
import os, sys
#import Image

class DataGroupException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)
        
class DataGroupFile(object):
    
    def __init__(self):
        self.__tag = ""
        self.__header = ""
        self.__body = ""
        self.__stop = False

    def _setHeader(self, value):
        self.__header = value
        if value != "":
            self.__tag = converter.toTAG(binToHexRep(value[0]))

    def _setBody(self, value):
        self.__body = value
        
    def _getHeader(self):
        return self.__header

    def _getBody(self):
        return self.__body

    def _getFile(self):
        return self.header + self.body
    
    def _setTag(self, tag):
        self.__tag = tag
    
    def _getTag(self):
        return self.__tag
    
    def _setStop(self, value):
        self.__stop = stop
        
    def _getStop(self):
        return self.__stop
    

    header = property(_getHeader, _setHeader, None, None)
    body = property(_getBody, _setBody, None, None)
    file = property(_getFile)
    tag = property(_getTag, _setTag)
        
class DataGroup(TLVParser, DataGroupFile):
    def __init__(self, dgf=None):
        DataGroupFile.__init__(self)
        if dgf:
            self.header = dgf.header
            self.body = dgf.body
        TLVParser.__init__(self, self.body)
        
    def _getTag(self):
        if ((binToHex(self._data[self._byteNb]) & 0x0F) == 0xF):
            tag = binToHexRep(self._data[self._byteNb:self._byteNb+2]).upper()
            self._byteNb += 2
        else:
            tag = binToHexRep(self._data[self._byteNb]).upper()
            self._byteNb += 1
        return tag
    
    def parse(self):
        try:
            TLVParser.parse(self)
            if self.__contains__("5C"):
                self["5C"] = self._parseDataElementPresenceMap(self["5C"])
        except TLVParserException as msg:
            raise DataGroupException(msg)
        
        return self
    
    def _parseDataElementPresenceMap(self, depm):
        """ 
        Convert concatenated bin tags into a list of string tag.
        
        >>> from pypassport.doc9303.datagroup import DataGroup, DataGroupFile
        >>> from pypassport.hexfunctions import *
        >>> header = None
        >>> body = hexRepToBin("5C0A5F0E5F115F425F125F13")
        >>> dgf = DataGroupFile()
        >>> dg = DataGroup(dgf)
        >>> res = dg._parseDataElementPresenceMap(body[0x02:])
        >>> res
        ['5F0E', '5F11', '5F42', '5F12', '5F13']
        
        @param depm: The data element presence map
        @type depm: A binary string 
        @return: A list with the tags found in the data element presence map.
        """
        byteNb = self._byteNb
        data = self._data
        
        self._byteNb = 0
        self._data = depm
        tags = []
        
        while self._byteNb < len(depm):
            tag = self._getTag()
            tags.append(tag)
            
        self._byteNb = byteNb
        self._data = data
        
        return tags
    
class DataGroup1(DataGroup):
    """  
    Implement the DataGroup1 parsing
    """
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
            
    def parse(self):
        super(DataGroup1, self).parse()
        data = self["5F1F"]
        docType = self._getMRZType(len(data))
        
        if docType == "TD1":
            self._parseTd1(data)
        elif docType == "TD2":
            self._parseTd2(data)
        elif docType == "TD3":
            self._parseTd3(data)            
            
        return self

    def _parseTd1(self, data):
     
        # doc code
        self["5F03"] = data[0:2]
        # issuing state
        self["5F28"] = data[2:5]
        # doc no (9 most significant digits)
        self["5A"] = data[5:14]
        # Check digit — Document number or filler character (<) indicating document number exceeds nine characters
        self["5F04"] = data[14:15]
        
        self["53"] = []
        
        # opt data or if doc no > 9 chars, least significant chars of doc no plus doc no check digit plus filler char
        if(self["5F04"].decode() == '<'):
            self["5A"] += data[15:28]
        else:
            self["53"].append(data[15:30])
        
        # DOB
        self["5F57"] = data[30:36]
        #check digit DOB
        self["5F05"] = data[36:37]
        #sex
        self["5F35"] = data[37:38]
        #DOE
        self["59"] = data[38:44]
        #check DOE
        self["5F06"] = data[44:45]
        #nationality
        self["5F2C"] = data[45:48]
        #opt data
        self["53"].append(data[48:59])
        #comp check 
        self["5F07"] = data[59:60]
        #name of holder
        self["5B"] = data[60:]

        
    def _parseTd2(self, data):
        # document code 2bytes TAG 5F03 
        self["5F03"] = data[0:2]
        # issuing state 3bytes TAG 5F28
        self["5F28"] = data[2:5]
        #name of holder 31bytes 
        self["5B"] = data[5:36]
        # Doc no 9bytes TAG 5A
        self["5A"] = data[36:45]
        # check digit 1byte TAG 5F04
        self["5F04"] = data[45:46]
        # Nationality 3bytes TAG 5F2C
        self["5F2C"] = data[46:49]
        # DOB 6bytes TAG 5F2B or 5F57
        self["5F57"] = data[49:55]
        # check digit 1byte TAG 5F05
        self["5F05"] = data[55:56]
        # Sex 1byte TAG 5F35
        self["5F35"] = data[56:57]
        # DOE 6bytes TAG 59
        self["59"] = data[57:63]
        # check digit 1byte TAG 5F06
        self["5F06"] = data[63:64]
        # Optional Data plus filler 14bytes TAG 53
        self["53"] = data[64:71]
        # composite check digit 1byte TAG 5F07
        self["5F07"] = data[71:72]        
        
    def _parseTd3(self, data):
        # document code 2bytes TAG 5F03 
        self["5F03"] = data[0:2]
        # issuing state 3bytes TAG 5F28
        self["5F28"] = data[2:5]
        # Name of holder 39bytes TAG 5B
        #self["5F5B"] = " ".join(list(filter(None,data[5:44].decode().split('<'))))
        self["5F5B"] = data[5:44]
        # Doc no 9bytes TAG 5A
        self["5A"]   = data[44:53]
        # check digit 1byte TAG 5F04
        self["5F04"] = data[53:54]
        # Nationality 3bytes TAG 5F2C
        self["5F2C"] = data[54:57]
        # DOB 6bytes TAG 5F2B or 5F57
        self["5F57"] = data[57:63]
        # check digit 1byte TAG 5F05
        self["5F05"] = data[63:64]
        # Sex 1byte TAG 5F35
        self["5F35"] = data[64:65]
        # DOE 6bytes TAG 59
        self["59"]   = data[65:71]
        # check digit 1byte TAG 5F06
        self["5F06"] = data[71:72]
        # Optional Data 14bytes TAG 53
        self["53"]   = data[72:86]
        # check digit 1byte TAG 5F02
        self["5F02"] = data[86:87]
        # composite check digit 1byte TAG 5F07
        self["5F07"] = data[87:88]
        
    def _getMRZType(self, length):
        if length == 0x5A:
            return "TD1"
        if length == 0x48:
            return "TD2"
        if length == 0x58:
            return "TD3"   
        return None
    
class DataGroup2(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
    def parse(self):
        self._byteNb = 0
        
        #7f61
        tag = self._getTag()
        length = self._getLength()
        
        #02
        tag = self._getTag()
        self[tag] = self._getValue()
        nbInstance = binToHex(self[tag])
        
        for x in range(nbInstance):
            #7F60
            tag = self._getTag()
            self._getLength()
            #A1
            templateID = self._getTag()
            #Read A
            v = self._getValue()
            dgf = DataGroupFile()
            dgf.body = v
            dg = DataGroup(dgf)
            dg.parse()
            data = dg
            #Transform the binary data into usable data
            for x in data:
                data[x] = binToHexRep(data[x])
            #5F2E or 7F2E
            tag = self._getTag()
            value = self._getValue()
            headerSize, data['meta'] = ISO19794_5.analyse(binToHexRep(value))
           
            data[tag] = value[headerSize:]
            
            self[templateID] = {}
            self[templateID] = data
            
        return self
            
class DataGroup3(DataGroup2):
    
    def __init__(self, dgFile):
        DataGroup2.__init__(self, dgFile)
        
class DataGroup4(DataGroup2):
    
    def __init__(self, dgFile):
        DataGroup2.__init__(self, dgFile)
        
class DataGroup5(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
    def parse(self):
        """
        The returned value is a dictionary with two keys:
            1. '02': The number of instances
            2. '5F40' or '5F43' : A list of displayed portrait or A list of displayed signature"
                The value is a list of list
        ex: 
            - {'02': [2], '5F40' : [[0x..,0x..,0x..], [0x..,0x..,0x..]]}
            - {'02': [1], '5F43' : [[0x..,0x..,0x..]]}
        
        Each values of the dictionnary are in a list of hexadecimal/decimal values. 
        """
        
        self._byteNb = 0
        tag = self._getTag()
        self[tag] = self._getValue()
        nbInstance = binToHex(self[tag])
        
        
        data = []
        
        for x in range(nbInstance):
            tag = self._getTag()
            data.append(self._getValue())
            
        self[tag] = data
        
        return self
        
class DataGroup6(DataGroup5):
    
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)
        
class DataGroup7(DataGroup5):
    
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)
        
        
class DataGroup8(DataGroup5):
    
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)
        
class DataGroup9(DataGroup5):
    
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)
        
class DataGroup10(DataGroup5):
    
    def __init__(self, dgFile):
        DataGroup5.__init__(self, dgFile)
        
class DataGroup11(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)

    def parse(self):
        super(DataGroup11, self).parse()
        
        if "5F2B" in self:
            if len(binToHexRep(self["5F2B"])) == 8:
                self["5F2B"] = binToHexRep(self["5F2B"])
                
        return self
                
class DataGroup12(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile) 
      
    def parse(self):
        super(DataGroup12, self).parse()
        
        if "5F26" in self:
            if len(binToHexRep(self["5F26"])) == 8:
                self["5F26"] = binToHexRep(self["5F26"])
                
        if "5F55" in self:
            if len(binToHexRep(self["5F55"])) == 14:
                self["5F26"] = binToHexRep(self["5F55"])
                
        return self
                
class DataGroup13(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
class DataGroup14(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)#Reserved for future use (RFU)
        
    def parse(self):
        return self
    
class DataGroup15(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
    def parse(self):
        return self
    
class DataGroup16(DataGroup):
    
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)   
        
    def parse(self):
         #Read the number of templates
         self._tagOffset = 0
         tag = self._getTag()
         nbInstance = binToHex(self._getValue())
         
         for i in range(nbInstance):
             #Read each Template Element
             tag = self._getTag()
             self[i] = self._parseTemplate(self._getValue())
             
         return self
             
class Com(DataGroup):
    """ 
    Implement the parsing of the com file
    """
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
class SOD(DataGroup):
    """ 
    Implement the sod parsing
    """
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
    def parse(self):
        return self

class CardAccess(DataGroup):
    """ 
    Implement the CardAccess parsing
    """
    def __init__(self, dgFile):
        DataGroup.__init__(self, dgFile)
        
    def parse(self):
        return self
        
class DataGroupFactory(Singleton, Logger):
    
    def __init__(self):
        Logger.__init__(self, "DataGroup")
    
    def create(self, dgFile):
        dg = eval(converter.toClass(dgFile.tag))(dgFile)
        try:
            dg.parse()
        except Exception as msg:
            self.log("Parsing failed: " + str(msg), converter.toDG(dg.tag))
        return dg
    
class Events(object):
    def __init__(self):
        self._listeners = []
        
    def register(self, fct):
        """the listener gives the method he want as callback"""
        self._listeners.append(fct)
        
    def unregister(self, listener):
        self._listeners.remove(listener)
        
    def log(self, msg):
        for listenerFct in self._listeners:
            listenerFct(msg)
                
class DataGroupReader(Logger):
    """   
    Read a specific dataGroup from the passport.
    This is the superclass defining the interface for the classes implementing the reading.
    """
    def __init__(self, iso7816, maxSize = 0xE0):
        """ 
        @param iso7816: The layer sending iso7816 apdu to the reader.
        @type iso7816: A iso7816 object
        @param maxSize: The maximum buffer size accepted by the reader.
        @type maxSize: An integer (hexa)
        """
        Logger.__init__(self, "DataGroupReader")
        self._iso7816 = iso7816
        
        self._file = DataGroupFile()
        self._bodySize = 0
        self._bodyOffset = 0    #The beginning of the body data
        self._offset = 0
        self._maxSize = maxSize
        self.processed = Events()

                
    def readDG(self, dg):
        """  
        Read the specified dataGroup and return the file in two parts:
        
        A dataGroup::
            6C 40 
                  5C   06     5F195F265F1A    
                  5F19 18     UNITED STATES OF AMERICA        
                  5F26 08     20020531
                  5F1A 0F     SMITH<<BRENDA<P
            
            1. The header::
                6C 40
            2. The body ::
                5C   06     5F195F265F1A    
                5F19 18     UNITED STATES OF AMERICA        
                5F26 08     20020531
                5F1A 0F     SMITH<<BRENDA<P

        """
        self.log("READ DG " + dg)
        self.stop = False
        self.offset = 0
        self._selectFile(dg)
        
        self._file = DataGroupFile()
        self._file.header = self._readHeader(dg)
        self._file.body = self._readBody()
        return self._file
            
    def _selectFile(self):
        raise DataGroupException("Should be implemented")
        
    def _readHeader(self, dg):
        header = self._iso7816.readBinary(self.offset, 4)
        (self._bodySize, self.offset) = asn1Length(header[1:])
        self.offset += 1
        self.log("Body Size: " + str(self._bodySize) + " Offset " + str(self.offset))        
        if(converter.toTAG(dg) != binToHexRep(header[0])):
            raise Exception("Wrong AID: " + binToHexRep(header[0]) + " instead of " +  converter.toTAG(dg))
        
        return header[:self.offset]
        
    def _readBody(self):
        body = b""
        toRead = self._bodySize
        while not self.stop and toRead > self._maxSize:
            tmp = self._iso7816.readBinary(self.offset, self._maxSize)
            body += tmp
            l = len(tmp)
            toRead -= l
            self.offset += l
            self.log("Read: " + str(l) + " Expected: " + str(self._maxSize))        

                    
        if self.stop:
            self.log('reading aborded')
            self.stop = False
            raise Exception("reading aborded")
            
        tmp = self._iso7816.readBinary(self.offset, toRead)
        l = len(tmp)
        self.offset += l
        body += tmp
        self.log("Read: " + str(l) + " Expected: " + str(toRead))        

        if self._bodySize != len(body):
            raise Exception("The file is not entirely read: expected: " + str(self._bodySize) + " read: " + str(len(body)))
        
        return body
    
    def _getOffset(self):
        return self._offset
    
    def _setOffset(self, value):
        self._offset = value
        l = len(self._file.header)
        if (l+self._bodySize != 0) and (l + value != 0):
            v = int((float(value) / float((len(self._file.header) + self._bodySize)))*100)
            self.processed.log(v)
    
    offset = property(_getOffset, _setOffset)

class FSDataGroupReader(DataGroupReader):
    """ 
    Implement the superClass dataGroupReader.
    Implement the reading using FS 
    """
    def __init__(self, iso7816, maxSize = 0xE0):
        DataGroupReader.__init__(self, iso7816, maxSize)
        
    def _selectFile(self, tag):
        self._iso7816.selectFile("02", "0C", converter.toFID(tag))

        
class SFIDataGroupReader(DataGroupReader):
    """ 
    Implement the superClass dataGroupReader.
    Implement the reading using ShortFileIdentifier
    """
    def __init__(self, iso7816, maxSize = 0xE0):
        DataGroupReader.__init__(self, iso7816, maxSize)
       
    def _selectFile(self, tag):
        #Read the AID + the body size
        SFI = (hexRepToHex(converter.toSEF(tag)) ^ 0x80) * 256
        self._offset = SFI
        
class DataGroupReaderFactory(Singleton):
    
    reader = {
            "FS": FSDataGroupReader,
            "SFI": SFIDataGroupReader,
        }
    
    def create(self, iso7816, reader="FS"):
        return self.reader[reader](iso7816)
    
class DataGroupDump(object):
    """ 
    Save the passport, a specific dataGroup or some data to the disk.
    """
    def __init__(self, path, ext=""):
        """  
        @param path: The path where the dump will be stored.
        @param ext: File extension
        @type path: A string
        @raise Exception: If the specified directory in invalid.
        """
        if os.path.isdir(path):
            self._path = path
            self._path += os.path.sep
            self._ext = ext
        else:
            raise Exception(path + " is not a valid directory")
        
    def dump(self, ep, format=converter.types.FID):
        """  
        Save the dataGroup binaries on the HDD.
        The name format is specified by the format parameter.
        
        @param ep: The EPassport object.
        @type ep: A dictionary
        @param format: Specify the file name format. (FID, TAG, SEF,...)
        @type format: An element out of the converter.types enumeration.
        """
        for tag in ep:
            self.dumpDG(ep[tag], format)
            
    def dumpDG(self, dg, format=converter.types.FID):
        """  
        Save the specified dataGroup on the HDD.
        
        @param dg: A filled dataGroup object
        @type dg: A dataGroup object
        @param format: Specify the file name format. (FID, TAG, SEF,...)
        @type format: An element out of the converter.types enumeration.
        """
        f = open(self._path + converter.to(format, dg.tag) + self._ext, "wb")
        f.write(dg.file)
        f.close()
        
    def dumpData(self, data, name):
        """  
        Save some data on the HDD. The data can be the binary of a picture for example.
        It will be saved under the name passed as parameter.
        
        @param data: The binary to save on the HDD
        @type data: A binary string
        @param name: The file name
        @type name: A string
        """
        if data == None:
            return
        f = open(self._path + name, "wb")
        f.write(data)
        f.close()
        
