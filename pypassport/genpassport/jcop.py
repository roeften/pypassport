from pypassport.externalCall import *
from pypassport import iso7816
from pypassport.doc9303 import converter, mrz, bac
from pypassport.apdu import CommandAPDU
from pypassport.hexfunctions import *
from pypassport.logger import Logger

class GPlatform(object):
    def __init__(self, readerNum):
        self._ec = ExternalCall()
        self._readerNum = readerNum
        
    def install(self, applet):
        """
        Set up the JCOP with the specified applet.
        JPShell must be installed and in the path
        
        @param applet: The applet location
        """
        
        if (applet == None) or (applet == ""):
            raise Exception("applet parameter unset")

        cmd = """mode_211
        enable_trace
        establish_context
        card_connect -readerNumber """ + str(self._readerNum) + """
        select -AID A000000003000000
        open_sc -security 3 -mac_key 404142434445464748494a4b4c4d4e4f -enc_key 404142434445464748494a4b4c4d4e4f -kek_key 404142434445464748494a4b4c4d4e4f
        delete -AID A00000024710
        install -file """ + str(applet) + """ -priv 2
        card_disconnect
        release_context"""
        
        self._ec.toDisk("setPassport.gpshell", cmd)
        res = None
        try:
            res = self._ec.execute("gpshell setPassport.gpshell")
            self.log(res)
        except Exception as msg:
            pass
        finally:
            self._ec.remFromDisk("setPassport.gpshell")    
            if res:
                if res.find("read_executable_load_file_parameters()") > -1:
                    raise Exception("Applet not found")
                if res.find("card_connect() returns 0x80100069") > -1:
                    raise Exception("Invalid reader number")
                
class JavaCardWritter(Logger):
    
    def __init__(self, reader, maxSize = 0xDF):
        """ 
        @param reader: A Reader
        @type Reader
        @param maxSize: The maximum buffer size accepted by the reader.
        @type maxSize: An integer (hexa)
        """
        Logger.__init__(self, "JCOP")
        self._maxSize = maxSize
        self._iso7816 = iso7816.Iso7816(reader)
        
    def writeDG(self, dg):
        file = converter.toFID(dg.tag)
        #File selection
        self._iso7816.selectFile("00", "00", file, cla="10", ins="A5")
        
        self._maxSize = 0xFA
        #Write binary
        writed = 0
        dgLength = len(dg.file)
        
        while writed < dgLength:
            toSend = dg.file[writed:writed+self._maxSize]
            self._iso7816.updateBinary(writed, toSend, cla="10", ins="A6")
            writed += len(toSend)
            
        self.log(str(dg.tag) + " sent to JCOP")
            
    def setKseed(self, dg1):
        l2 = dg1["5F1F"][44:]
        b = bac.BAC(None)
        m = mrz.MRZ(l2)
        m.checkMRZ()
        kseed = binToHexRep(b.mrz_information(m))
        toSend = CommandAPDU("10", "A7", "00", "00", "18", kseed, "")
        self._iso7816.transmit(toSend, "Set KSeed")
        
        self.log("Kseed set")
        
