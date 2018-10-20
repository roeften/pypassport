from .datagroupcreation import * 
from pypassport.genpassport.jcop import *
from pypassport.doc9303 import converter
from pypassport import iso7816
    
class EPassportCreator(Logger):
    
    def __init__(self, ds, dsKey, reader=None):
        """  
        @param ds: The Document Sgner certificate in PEM
        @param dsKey: The associated ds private key
        """
        Logger.__init__(self, "EPCreation")
        self._ds = ds
        self._dsKey = dsKey
        if reader: self._iso7816 = iso7816.Iso7816(reader)
        else: self._iso7816 = None
        
        self._jcopW = JavaCardWritter(reader)
        
        self._openssl = OpenSSL()
        self._forged = None
        self._openssl.register(self._traceOpenssl)
        
    def setEPassport(self, ep):
        self._forged = []
        
        for x in ep:
            if x not in( converter.toTAG("DG15"), converter.toTAG("Common")):
                self._forged.append(ep[x])
        
        #Forge a Common file without DG15
        self._forged.append(ComCreation().create(self._forged))
        

    def toDisk(self, type=converter.types.GRT, ext="", path="."):
        """
        Write the data groups on disk.
        
        @param type: The output file format. See convert.py for the options
        @param ext: The output extension file.
        """
        
        if not self._forged:
            raise Exception("The method create must be called first")
        
        dgd = DataGroupDump(path, ext)
        for dg in self._forged:
            dgd.dumpDG(dg, type)

    def toJCOP(self):
        """ 
        Write the forged passport into a JCOP (with the JMRTD applet installed).
        @param reader: The reader object connected to the JCOP.
        @passport: If not specified, write the passport forger with the previous call of the forge method.
                    Else, install the given passport on the JCOP. (must contains at least the keys DG1, DG2, Common, SecurityData).
        """
            
        if not self._forged:
            raise Exception("The method create must be called first")
        
        if not self._iso7816:
            raise Exception("The object must be initialized with a reader")
        
        mrz = None
        for dg in self._forged:
            self._jcopW.writeDG(dg)
            if dg.tag == '61':
                self._jcopW.setKseed(dg)
                mrz = dg["5F1F"][44:] 
        return mrz     

    def create(self, issuer, name, firstname, nat, sex, passportID, birthDate, expiryDate, imgPath, signPath=None, birthplace=None, authority=None, issueDate=None):
        self._forged = []
        
        try:
            self._forged.append(DataGroup1Creation().create("P", issuer, name, firstname, nat, sex, passportID, birthDate, expiryDate))
            self.log("DG1 forged")
            
            self._forged.append(DataGroup2Creation().create(imgPath))
            self.log("DG2 forged")
            
            if signPath:
                self._forged.append(DataGroup7Creation().create(signPath))
                self.log("DG7 forged")
                
            if birthplace:
                self._forged.append(DataGroup11Creation().create(birthplace))
                self.log("DG11 forged")
            
            if authority and issueDate:
                self._forged.append(DataGroup12Creation().create(authority, issueDate))
                self.log("DG12 forged")
                
            com = ComCreation().create(self._forged)
            self.log("Com forged")
    
            self._forged.append(SODCreation().create(self._ds, self._dsKey, self._forged))
            self.log("SOD forged")

            self._forged.append(com)
            
        except Exception as msg:
            self.log(str(msg))
            self._forged = None
            raise Exception(msg)
        
    def _traceOpenssl(self, name, msg):
        self.log(msg, name)
        
    
