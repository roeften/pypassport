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

import os, sys, time

from pypassport import hexfunctions
from .apdu import CommandAPDU, ResponseAPDU
from smartcard.util import *
from pypassport.apdu import CommandAPDU, ResponseAPDU
from pypassport.hexfunctions import *
from pypassport.singleton import Singleton
from pypassport.logger import Logger
from pypassport.doc9303 import converter

if sys.platform == 'win32':
    f = os.popen("net start scardsvr", "r")
    res = f.read()
    f.close()

class ReaderException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class Reader(Logger):
    
    readerName = None
    readerNum = None
    
    def __init__(self):
        Logger.__init__(self, "READER")
    
    def connect(self, readerNum=None):
        """ 
        If there is some reader connected to the computer, we have to specify to which one we want to connect.
        
        @param readerNum: The reader number.
        @type readerNum: An integer.
        """
        raise Exception("Should be implemented")
    
    def transmit(self, APDU):
        """ 
        The method send the apdu to the reader and return the ICC answer
        
        @param APDU: The apdu to transmit to the reader
        @type APDU: A commandAPDU object
        @return: A resultAPDU object with the ICC answer.
        """
        raise Exception("Should be implemented")
        
    def disconnect(self):
        """ 
        To release the reader.
        """
        raise Exception("Should be implemented")
        
    def getReaderList(self):
        raise Exception("Should be implemented")
    
    
class DumpReader(Reader):
    """
    The class adds two properties:
    format: the file naming convention
    ext: the file extension
    """
    def __init__(self):
        self._file = None
        self.format = "GRT"
        self.ext = ".bin"
    
    def connect(self, path):
        if os.path.isdir(str(path)):
            self.readerNum = path + os.sep
            return True
        return False 
    
    def transmit(self, apdu):
        if apdu.ins == "A4":
            if apdu.data == "A0000002471001":
                #Passport AID
                pass
            else:
                #SelectFile
                try:
                    if self._file:
                        self._file.close()
                    self._file = open(self.readerNum + converter.to(self.format, apdu.data) + self.ext, "rb")
                except Exception as msg:
                    return ResponseAPDU(str(msg), 0x6A, 0x82)
            return ResponseAPDU("", 0x90, 0x00)
        
        elif apdu.ins == "B0":
            #ReadBinary
            try:
                offset = hexRepToHex(apdu.p1 + apdu.p2)
                self._file.seek(offset)
                res = self._file.read(hexRepToHex(apdu.le))
                return ResponseAPDU(res, 0x90, 0x00)
            except Exception as msg:
                return ResponseAPDU(str(msg), 0x6A, 0x88)
            
        #Function not supported
        return ResponseAPDU("", 0x6A, 0x81)
            
    def disconnect(self):
        if self._file:
            self._file.close()
            
    def getReaderList(self):
        return ["Simulator"]

class PcscReader(Reader):
    def __init__(self):
        Reader.__init__(self)
        self.importSC()
        self._pcsc_connection = None
        
    def importSC(self):
        try:
            import smartcard
            self.sc = smartcard
        except:
            if sys.platform == 'darwin':
                msg =  "The smart card service/daemon is not started.\n"
                msg += "Please insert a reader and restart the application." 
            elif sys.platform == 'win32':
                msg =  "The smart card service is not started.\n"
                msg += "Please execute the following command in your os shell: \n"
                msg += "Windows: net start scardsvr"
            else: 
                msg =  "The smart card daemon is not started.\n"
                msg += "Please execute the following command in your os shell: \n"
                msg += "Linux: sudo /etc/init.d/pcscd start"
            raise ReaderException(msg)        
        
    def connect(self, rn):
        if rn in range(len(self.getReaderList())):
            self.readerNum = rn
            self.readerName = self.getReaderList()[rn]
            try:
                self._pcsc_connection = self.getReaderList()[rn].createConnection()
                # self.sc.scard.SCARD_PCI_T0
                self._pcsc_connection.connect()
                return True
            except self.sc.Exceptions.NoCardException as msg:
                return False
        raise ReaderException("The reader number is invalid")
    
    def disconnect(self):
        self._pcsc_connection.disconnect()
    
    def transmit(self, APDU):
        try:
            self.log(APDU)
            res = self._pcsc_connection.transmit(APDU.getHexListAPDU())
            rep = ResponseAPDU(hexListToBin(res[0]), res[1], res[2])
            self.log(rep)
            return rep
        except self.sc.Exceptions.CardConnectionException as msg:
            raise ReaderException(msg)
        
    def getReaderList(self):
        return self.sc.System.readers()
    
class apduWrapper(object):
    def __init__(self, data):
        self._apdu = data
        
    def getHexListAPDU(self):
        return self._apdu

class Acr122(PcscReader):

    Control = {     "AntennaPowerOff" :  [0x01, 0x00], 
                    "AntennaPowerOn" :   [0x01, 0x01],
                    "ResetTimer" :       [0x05, 0x00, 0x00, 0x00]
              }
    
    Polling = {     "ISO14443A": [0x01, 0x00]
              }
    
    Speed = {       "212 kbps" : [0x01, 0x01, 0x01],
                    "424 kbps" : [0x01, 0x02, 0x02]
            }
    
    Pseudo_APDU = { "DirectTransmit" :  [0xFF, 0x00, 0x00, 0x00],
                    "GetResponse" :     [0xFF, 0xC0, 0x00, 0x00]
                   }
    
    PN532_Cmd = {   "InListPassiveTarget" : [0xD4, 0x4A, 0x01, 0x01],
                    "InDataExchange" :      [0xD4, 0x40, 0x01],
                    "Control" :             [0xD4, 0x32],
                    "Polling" :             [0xD4, 0x4A],
                    # Change to Baud Rate 424 kbps
                    "Speed" :               [0xD4, 0x4E]
                    
                }
    
    Errors = {0x61: 'SW2 Bytes left to read',
              0x63:{0x00:'The operation is failed.',
                    0x01:'The PN532 does not response.',
                    0x27: 'Command not acceptable in context of PN532',
                    #0x27:'The checksum of the Contactless Response is wrong.',
                    0x7F:'The PNNAME = "GENERIC PC/SC"532_Contactless Command is wrong.'},
              0x90: 'Success'
              }
    
    def __init__(self):
        PcscReader.__init__(self)
    
    def connect(self, rn=None):
        if super(Acr122, self).connect(rn):
            res = self.transmit(apduWrapper(Acr122.Control["AntennaPowerOff"]),"Control")
            res = self.transmit(apduWrapper(Acr122.Control["AntennaPowerOn"]),"Control")
            res = self.transmit(apduWrapper(Acr122.Control["ResetTimer"]),"Control")
            res = self.transmit(apduWrapper(Acr122.Polling["ISO14443A"]),"Polling")
            res = self.transmit(apduWrapper(Acr122.Speed["424 kbps"]),"Speed")
            return True
        
    def transmit(self, APDU, PN532_Cmd="InDataExchange"):
        # Send Command
        hexListAPDU = APDU.getHexListAPDU()
        wrappedApdu = Acr122.Pseudo_APDU["DirectTransmit"] + [len(Acr122.PN532_Cmd[PN532_Cmd]) + len(hexListAPDU)] + Acr122.PN532_Cmd[PN532_Cmd] + hexListAPDU
        
        res = self._pcsc_connection.transmit(wrappedApdu)
        # Check if there is data to read 
        try:
            # Error Handling
            if res[1] == 0x61:
                wrappedApdu =  Acr122.Pseudo_APDU["GetResponse"] + [res[2]]
                res = self._pcsc_connection.transmit(wrappedApdu)
                # Error Handling
                msg = Acr122.Errors[res[1]]
                if msg == "Success":
                    data, sw1, sw2 = self._removePN532Header(res[0])
                    return ResponseAPDU(hexListToBin(data), sw1, sw2)
                else:
                    raise ReaderException(Acr122.Errors[res[1]][res[2]])
                
            else:
                try:
                    err = Acr122.Errors[res[1]][res[2]]
                except Exception:
                    err = "Unknown error"
                    
                raise ReaderException(err)

        except KeyError:
            #Unknown error from acr122
            #Checked in the upper layer
            data, sw1, sw2 = self._removePN532Header(res[0])
            return ResponseAPDU(hexListToBin(data), sw1, sw2)

    def _removePN532Header(self,data):
        # direct transmit or speed change response -- 3 bytes of header
        if (data[0:2] == [0xD5, 0x41] or data[0:2] == [0xD5, 0x4F]) and data[2] == 0x00:
            return data[3:-2], data[-2], data [-1]
        # otherwise 2 byte of header
        return data[2:-2], data[-2], data [-1]
    
class TimeOutException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)
    
class ReaderManager(Singleton):
    """
    Manage the readers.
    """

    #The driver for a kind of reader. The ACR122 is a special case of the PCSC Reader
    readers = {
            PcscReader.__name__: PcscReader,
            Acr122.__name__: Acr122,
            DumpReader.__name__ : DumpReader
        }
    
    def __init__(self):
        self._blackList = [Acr122.__name__, DumpReader.__name__]
    
    def create(self, reader="PcscReader"):
        """
        Create a new instance of the specified driver
        """
        try:
            return ReaderManager.readers[reader]()
        except KeyError:
            raise ReaderException("Unsupported reader: " + str(reader))
    
    def getReaderList(self):
        res = []
        for rt in self.readers:
            if not self._filter(rt):
                res += self.create(rt).getReaderList()
        return res
    
    def _filter(self, reader):
        try:
            self._blackList.index(reader)
            return True
        except ValueError:
            return False
    
    def _autoDetect(self):
        """   
        Pool every connected reader with every driver available by the factory.
        When a couple (driver, num reader) can select the AID, we have a good reader!
        Return a couple (reader object, reader number, reader name)
        """
        for driver in ReaderManager.readers:
            r = self.create(driver)
            
            for numR in range(len(self.getReaderList())):
                try:
                    if r.connect(numR):
                        res = r.transmit(CommandAPDU("00", "A4", "04", "0C", "07", "A0000002471001"))
                        if res.sw1 == 0x90 and res.sw2 == 0x00:
                            return r
                except ReaderException as msg:
                    r.disconnect()
        
        return None  
    
    def waitForCard(self, timeout=15, driver=None, readerNum=None):
        
        """  
        Wait until a card is put on a reader. 
        After I{timeout} seconds, the loop is break and an TimeOutException is raised
        If I{driver} and I{readerNum} are let to none, the wait for loop will pool on every reader with every driver until a match is found.
        If I{driver} and I{readerNum} are both set, the loop  will pool on the specified reader with the specified driver.
        By default, the time-out is set to 15 seconds.
        
        @param timeout: The timeout in second the loop wait for a card before being interrupted.
        @type timeout: Integer
        @param driver: The driver to use during the pooling
        @type driver: A class inheriting from Reader 
        @param readerNum: The reader to pool on
        @type readerNum: Integer
        
        @raise TimeOutException: Is the time-out expires, the exception is raised.
        
        """
        cpt = 0
        wait = 0.5
        
        if driver == None and readerNum == None:
            r = self._autoDetect()
            while not r and cpt < timeout:
                r = self._autoDetect()
                time.sleep(wait)
                cpt += wait
            if cpt == timeout:
                raise TimeOutException("Time-out")
            return r
    
        else:
            reader = self.create(driver)
            while not reader.connect(readerNum) and cpt < timeout:
                time.sleep(wait)
                cpt += wait
            if cpt == timeout:
                raise TimeOutException("Time-out")
            return reader