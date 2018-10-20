from pypassport.doc9303 import converter, mrz
from pypassport.openssl import OpenSSL, OpenSSLException
from pypassport.logger import Logger
from pypassport.doc9303.datagroup import *
from pypassport.derobjectidentifier import *
from pypassport.asn1 import *
        
class DataGroupFileCreation(DataGroupFile):
    """  
    The purpose of this class is to create a fake dataGroup.
    """
    def __init__(self, aid):
        """  
        @param aid: The dataGroup tag
        @type aid: A string
        """
        DataGroupFile.__init__(self)
        self.tag = aid
    
    def addDataObject(self, tag, value):
        """ 
        Insert a new tag, value couple inside the dataGroup.
        
        @param tag: A tag in hexRep format
        @type tag: A string
        @param value: The value associated to the tag
        @type value: A string       
        """
        length = binToHexRep(toAsn1Length(len(value)))
        tmp = hexRepToBin(tag) + hexRepToBin(length) + value
        self.body += tmp
    
    def getHeader(self):
        return hexRepToBin(self.tag) + toAsn1Length(len(self.body))
        
    def setHeader(self, value):
        super(DataGroupFileCreation, self).setHeader(value)
        
    header = property(getHeader, setHeader, None, None)
    
class Creation(Logger):
    def __init__(self):
        Logger.__init__("Creation")
    
    def create(self):
        raise Exception("Should be implemented")
        
    def _convertDate(self, date):
        if len(date) != 6:
            raise Exception("The date length is wrong")
        return date[4:6] + date[2:4] + date[0:2]
    
class ComCreation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("Common"))
        
    def create(self, dgs, LDSvn="30313037", Uvn="303430303030"):
        self._dgc.addDataObject("5F01", hexRepToBin(LDSvn))
        self._dgc.addDataObject("5F36", hexRepToBin(Uvn))
        
        dgsList = ""
        for dg in dgs:
            if dg.tag != '60' and dg.tag != '77':
                dgsList += str(dg.tag).upper()
        self._dgc.addDataObject("5C", hexRepToBin(dgsList))
        
        return Com(self._dgc).parse()
        
class DataGroup1Creation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("DG1"))
        
    def create(self, type, issuer, name, surname, nat, sex, passportID, birthDate, expiryDate):
        m = mrz.MRZ(None)
        forgedMRZ = m.buildMRZ(type, issuer, name, surname, nat, sex, passportID, self._convertDate(birthDate), self._convertDate(expiryDate))
        
        self._dgc.addDataObject("5F1F", forgedMRZ)
        
        return DataGroup1(self._dgc).parse()
    
class DataGroup2Creation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("DG2"))
        
    def create(self, imgPath):
        
        f = open(imgPath, 'rb')
        img = f.read()
        f.close()
        try:
            import Image
            width,height = Image.open(imgPath).size
        except:
            width = 0
            height = 0
        
        #Biometric Header Template
        bht = DataGroupFileCreation("A1")
        bht.addDataObject("87", hexRepToBin("0101"))
        bht.addDataObject("88", hexRepToBin("0008"))
        
        #Biometric Data Block
        bdb = DataGroupFileCreation("5F2E")
        bdb.body = ISO19794_5.createHeader('JPG', width, height, len(img)) + img
        
        #Biometric Information Group Template
        bigt = DataGroupFileCreation("7F61")
        bigt.addDataObject("02", hexRepToBin("01"))
        bigt.addDataObject("7F60", bht.file + bdb.file)
        
        self._dgc.body = bigt.file
        
        return DataGroup2(self._dgc).parse()
        
class DataGroup7Creation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("DG7"))
        
    def create(self, signPath):
        f = open(signPath, 'rb')
        self._dgc.addDataObject("02", hexRepToBin("01"))
        self._dgc.addDataObject("5F43", f.read())
        f.close()
        
        return DataGroup7(self._dgc).parse()
        
class DataGroup11Creation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("DG11"))
        
    def create(self, birthplace):
        self._dgc.addDataObject("5C", hexRepToBin("5F11"))
        self._dgc.addDataObject("5F11", birthplace)
        
        return DataGroup11(self._dgc).parse()
        
class DataGroup12Creation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("DG12"))
        
    def create(self, authority, issueDate):
        self._dgc.addDataObject("5C", hexRepToBin("5F195F26"))
        self._dgc.addDataObject("5F19", authority)
        self._dgc.addDataObject("5F26", self._convertDate(issueDate)) # DDMMYYYY => YYYYMMDD
        
        return DataGroup12(self._dgc).parse()
        
    def _convertDate(self, date):
        if len(date) != 8:
            raise Exception("The date length is wrong")
        return date[4:8] + date[2:4] + date[0:2]
        
class SODCreation(Creation):
    def __init__(self):
        self._dgc = DataGroupFileCreation(converter.toTAG("SecurityData"))
        self._hashAlgo = "sha1"
        self._openssl = OpenSSL()
        
    def create(self, ds, dsKey, dgs):
        sodContent = self._createSODContent(dgs)
        self._dgc.body = self._openssl.signData(sodContent, ds, dsKey)
        
        return SOD(self._dgc).parse()
    
    def _createSODContent(self, dgs):
        self._hashAlgo = "sha1"
        hashes = self._calculateHashes(dgs)
        
        lds = LDSSecurityObject()
        lds.setComponentByName('version', 0)
        
        ai = AlgorithmIdentifier()
        ai.setComponentByName('algorithm', ObjectIdentifier(OIDrevert[self._hashAlgo]))
        ai.setComponentByName('parameters', Null(''))
        lds.setComponentByName('hashAlgorithm', ai)
        
        dghv = DataGroupHashValues()
        
        keys = list(hashes.keys())
        keys.sort()
        cpt=0
        for hashNb in keys:
            dgh = DataGroupHash()
            dgh.setComponentByName('dataGroupNumber', Integer(hashNb))
            dgh.setComponentByName('dataGroupHashValue', OctetString(hashes[hashNb]))
            dghv.setComponentByPosition(cpt, dgh)
            cpt+=1
            
        lds.setComponentByName('dataGroupHashValues', dghv)
        
        return encoder.encode(lds)
      
    def _calculateHashes(self, dgs):
        hashes = {}
        hashAlgo = eval(self._hashAlgo)
        for dg in dgs:
            if dg.tag != '60' and dg.tag != '77':
                res = hashAlgo(dg.file)
                hashes[converter.toOrder(dg.tag)] = res.digest()
            
        return hashes
    
