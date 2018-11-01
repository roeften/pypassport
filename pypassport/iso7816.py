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

from pypassport.reader import ReaderException
from pypassport.hexfunctions import *
from pypassport import apdu
from pypassport.logger import Logger

class Iso7816Exception(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)
    def __getitem__(self, i):
        return self.args[i]       

class Iso7816(Logger):
    
    Errors = {
                0x61:'SW2 indicates the number of response bytes still available',
                0x62:{0x00:'No information given',\
                      0x81:'Part of returned data may be corrupted',\
                      0x82:'End of file/record reached before reading Le bytes',\
                      0x83:'Selected file invalidated',\
                      0x84:'FCI not formatted according to ISO7816-4 section 5.1.5'},
                0x63:{0x00:'No information given',\
                      0x81:'File filled up by the last write',\
                      0x82:'Card Key not supported',\
                      0x83:'Reader Key not supported',\
                      0x84:'Plain transmission not supported',\
                      0x85:'Secured Transmission not supported',\
                      0x86:'Volatile memory not available',\
                      0x87:'Non Volatile memory not available',\
                      0x88:'Key number not valid',\
                      0x89:'Key length is not correct',\
                      0xC0:'Counter provided by 0 (exact meaning depending on the command)',\
                      0xC1:'Counter provided by 1 (exact meaning depending on the command)',\
                      0xC2:'Counter provided by 2 (exact meaning depending on the command)',\
                      0xC3:'Counter provided by 3 (exact meaning depending on the command)',\
                      0xC4:'Counter provided by 4 (exact meaning depending on the command)',\
                      0xC5:'Counter provided by 5 (exact meaning depending on the command)',\
                      0xC6:'Counter provided by 6 (exact meaning depending on the command)',\
                      0xC7:'Counter provided by 7 (exact meaning depending on the command)',\
                      0xC8:'Counter provided by 8 (exact meaning depending on the command)',\
                      0xC9:'Counter provided by 9 (exact meaning depending on the command)',\
                      0xCA:'Counter provided by 10 (exact meaning depending on the command)',\
                      0xCB:'Counter provided by 11 (exact meaning depending on the command)',\
                      0xCC:'Counter provided by 12 (exact meaning depending on the command)',\
                      0xCD:'Counter provided by 13 (exact meaning depending on the command)',\
                      0xCE:'Counter provided by 14 (exact meaning depending on the command)',\
                      0xCF:'Counter provided by 15 (exact meaning depending on the command)'},
                0x64:'State of non-volatile memory unchanged (SW2=00, other values are RFU)',
                0x65:{0x00:'No information given',\
                      0x81:'Memory failure'},
                0x66:'Reserved for security-related issues (not defined in this part of ISO/IEC 7816)',
                0x67:{0x00:'Wrong length'},
                0x68:{0x00:'No information given',\
                      0x81:'Logical channel not supported',\
                      0x82:'Secure messaging not supported'},
                0x69:{0x00:'No information given',\
                      0x81:'Command incompatible with file structure',\
                      0x82:'Security status not satisfied',\
                      0x83:'Authentication method blocked',\
                      0x84:'Referenced data invalidated',\
                      0x85:'Conditions of use not satisfied',\
                      0x86:'Command not allowed (no current EF)',\
                      0x87:'Expected secure messaging data objects missing',\
                      0x88:'Incorrect secure messaging data objects'},
                0x6A:{0x00:'No information given',\
                      0x80:'Incorrect parameters in the data field',\
                      0x81:'Function not supported',\
                      0x82:'File not found',\
                      0x83:'Record not found',\
                      0x84:'Not enough memory space in the file',\
                      0x85:'Lc inconsistent with TLV structure',\
                      0x86:'Incorrect parameters P1-P2',\
                      0x87:'Lc inconsistent with P1-P2',\
                      0x88:'Referenced data not found',\
                      0x89:'File already exists',\
                      0x8A:'DF name already exists'},
                0x6B:{0x00:'Wrong parameter(s) P1-P2'},
                0x6C:'Wrong length Le: SW2 indicates the exact length',
                0x6D:{0x00:'Instruction code not supported or invalid'},
                0x6E:{0x00:'Class not supported'},
                0x6F:{0x00:'No precise diagnosis'},
                0x90:{0x00:'Success'} #No further qualification
     }     
       
    def __init__(self, reader):
        Logger.__init__(self, "ISO7816")
        self._reader = reader
        self._ciphering = False

    def transmit(self, toSend, logMsg):
        """
        @param toSend: The command to transmit.
        @type toSend: A commandAPDU object.
        @param logMsg: A log message associated to the transmit.
        @type logMsg: A string.
        @return: The result field of the responseAPDU object
        
        The P1 and P2 fields are checked after each transmit.
        If they don't mean succes, the appropriate error string is retrieved 
        from the Error dictionary and an APDUException is raised.
        The Iso7816Exception is composed of three fields: ('error message', p1, p2)
        
        To access these fields when the exception is raised,
        acces the APDUException object like a list::
        
            try:
                x.apduTransmit(commandAPDU(..))
            except Iso7816Exception, exc:
                print "error: " + exc[0]
                print "(pw1, pw2) + str( (exc[1], exc[2]) )
        """
        try:
            self.log(logMsg)
            
            self.log(str(toSend))
            if self._ciphering:
                toSend = self._ciphering.protect(toSend)
                self.log("[SM] " + str(toSend))
            
            res = self._reader.transmit(toSend)
            
            if self._ciphering:
                self.log("[SM] " + str(res))
                res = self._ciphering.unprotect(res)
                
            msg = Iso7816.Errors[res.sw1][res.sw2]
            
            self.log(str(res)+" // " + msg)
            
            if msg == "Success":
                return res.res
            else:
                raise Iso7816Exception(msg, res.sw1, res.sw2)
        except KeyError as k:
            raise Iso7816Exception("Unknown error", res.sw1, res.sw2)  
        
    def setCiphering(self, c=False):
        self._ciphering = c 
            
    def selectFile(self, p1, p2, file="", cla="00", ins="A4"):
        lc = hexToHexRep(int(len(file)/2))
        toSend = apdu.CommandAPDU(cla, ins, p1, p2, lc, file, "")   
        return self.transmit(toSend, "Select File")
    
    def readBinary(self, offset, nbOfByte):
        os = "%04x" % int(offset)
        toSend = apdu.CommandAPDU("00", "B0", os[0:2], os[2:4], "", "", hexToHexRep(nbOfByte))
        return self.transmit(toSend, "Read Binary")
    
    def updateBinary(self, offset, data, cla="00", ins="D6"):
        os = "%04x" % int(offset)
        data = binToHexRep(data)
        lc = hexToHexRep(len(data)/2) 
        toSend = apdu.CommandAPDU(cla, ins, os[0:2], os[2:4], lc, data, "")
        return self.transmit(toSend, "Update Binary")
        
    def getChallenge(self):
        toSend = apdu.CommandAPDU("00", "84", "00", "00", "", "", "08")
        return self.transmit(toSend, "Get Challenge")
    
    def internalAuthentication(self, rnd_ifd):
        data = binToHexRep(rnd_ifd)
        lc = hexToHexRep(int(len(data)/2)) 
        toSend = apdu.CommandAPDU("00", "88", "00", "00", lc, data, "00")
        res = self.transmit(toSend, "Internal Authentication")
        return res
        
    def reset(self):
        self.setCiphering()
        self._reader.disconnect()
        self._reader.connect(self._reader.readerNum)
    
#    def mutualAuthentication(self, data):
#        data = binToHexRep(data)
#        lc = hexToHexRep(len(data)/2) 
#        toSend = apdu.CommandAPDU("00", "82", "00", "00", lc, data, "28")
#        return self.transmit(toSend, "Mutual Authentication")
