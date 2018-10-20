from pypassport.openssl import OpenSSL, OpenSSLException
from .logger import Logger
import os

class DistinguishedName(object):
    def __init__(self, C="", ST="", L="", O="", OU="", CN="", emailAddress="", serialNumber=""):
        self.__C = C
        self.__ST = ST
        self.__L = L
        self.__O = O
        self.__OU = OU
        self.__CN = CN
        self.__emailAddress = emailAddress
        self.__serialNumber = serialNumber

    def getC(self):
        return self.__C

    def getST(self):
        return self.__ST

    def getL(self):
        return self.__L

    def getO(self):
        return self.__O

    def getOU(self):
        return self.__OU

    def getCN(self):
        return self.__CN

    def getEmailAddress(self):
        return self.__emailAddress

    def getSerialNumber(self):
        return self.__serialNumber

    def setC(self, value):
        self.__C = value

    def setST(self, value):
        self.__ST = value

    def setL(self, value):
        self.__L = value

    def setO(self, value):
        self.__O = value

    def setOU(self, value):
        self.__OU = value

    def setCN(self, value):
        self.__CN = value

    def setEmailAddress(self, value):
        self.__emailAddress = value

    def setSerialNumber(self, value):
        self.__serialNumber = value

    
    def getSubject(self):
        subj = ""
        if self.C: subj += "/C="+self.C
        if self.ST: subj += "/ST="+self.ST
        if self.L: subj += "/L="+self.L
        if self.O: subj += "/O="+self.O
        if self.OU: subj += "/OU="+self.OU
        if self.CN: subj += "/CN="+self.CN
        if self.emailAddress: subj += "/emailAddress="+self.emailAddress
        if self.serialNumber: subj += "/serialNumber="+self.serialNumber
        return '"' + subj + '"'

    C = property(getC, setC, None, None)
    ST = property(getST, setST, None, None)
    L = property(getL, setL, None, None)
    O = property(getO, setO, None, None)
    OU = property(getOU, setOU, None, None)
    CN = property(getCN, setCN, None, None)
    emailAddress = property(getEmailAddress, setEmailAddress, None, None)
    serialNumber = property(getSerialNumber, setSerialNumber, None, None)
    
class CA(Logger):
    def __init__(self, caLoc=os.path.expanduser('~'), csca=None, cscaKey=None, opensslLocation=""):
        """ 
        Initiate the CA infrastructure.
        @caLoc: The location where the openssl config files will be stored 
        @param csca: An existing CSCA Certificate in PEM
        @param cscaKey: The private key of the CSCA in PEM
        @param opensslLocation: The openssl executable location 
        """
        Logger.__init__(self, "CA")
        
        self._csca = csca
        self._cscaKey = cscaKey
        self._loc = os.path.normpath(caLoc)
        self._loc = os.path.join(self._loc, 'ca')
        self._configFile = os.path.join(self._loc, 'openssl.cfg')
        
        try:
            os.mkdir(self._loc)
        except:
            pass
        
        self._openssl = OpenSSL('"' + self._configFile + '"')
        self._openssl.register(self._traceOpenSSl)
        
    def createCSCA(self, size=1024, days=720, dn=DistinguishedName(C="BE", O="Gouv", CN="CSCA-BELGIUM")):
        """ 
        Create a Country Signing Certificate Authority.
        Return a couple with the x509 as first item and the private key as second item
        
        The default distinguished name for the CSCA is:
        C=BE
        O=Gouv
        CN=CSCA-BELGIUM
        
        @param size: The RSA key size in bits
        @param days: The validity period of the certificate
        @param dn: The distinguised name of the certificate
        @return: (x509, privateKey) both in PEM
        """
        self._cscaKey = self._openssl.genRSAprKey(size)
        self._csca = self._genRootHelper(self.cscaKey, days, dn) 
        return (self.csca, self.cscaKey)
    
    def _genRootHelper(self, cscaKey, days, dn):
        try:
            return self._openssl.genRootX509(cscaKey, days, dn)
        except OpenSSLException as msg:
            msg = str(msg)
            self._errorHandler(msg)
            return self._openssl.genRootX509(cscaKey, days, dn)
             
        
    def createDS(self, size=1024, days=365, dn=DistinguishedName(C="BE", O="Gouv", CN="Document-Signer-BELGIUM")):
        """ 
        Create a Document Signer Certificate.
        Return a couple with the x509 as first item and the private key as second item
        
        The default distinguished name for the DS is:
        C=BE
        O=Gouv
        CN=Document Signer BELGIUM
        
        @param size: The RSA key size in bits
        @param days: The validity period of the certificate
        @param dn: The distinguised name of the certificate
        @return: (x509, privateKey) both in PEM
        """
        self._testinit()
        dsKey = self._openssl.genRSAprKey(size)
        dsReq = self._openssl.genX509Req(dsKey, dn)
        ds = self._signX509Helper(dsReq, days)    
            
        return (ds, dsKey)
    
    def _signX509Helper(self, dsReq, days):
        try:
            return self._openssl.signX509Req(dsReq, self.csca, self.cscaKey, days)
        except OpenSSLException as msg:
            msg = str(msg)
            self._errorHandler(msg)
            return self._signX509Helper(dsReq, days)
    
    def revoke(self, x509):
        """   
        Revoke the certificate.
        Return the CRL in PEM.
        
        @param x509: A x509 certificate
        @return: The CRL in PEM
        @rtype: A string
        """
        self._testinit()
        self._openssl.revokeX509(x509, self.csca, self.cscaKey)
        
    def _traceOpenSSl(self, name, msg):
        self.log(msg, name)
    
    def getCrl(self):
        if not os.path.isfile(os.path.join(self._loc, 'crlnumber')):
            self._openssl._toDisk(os.path.join(self._loc, 'crlnumber'), "01")
            self.log("echo '01' > ca/cerlnumber")
        try:
            crl = self._openssl.genCRL(self.csca, self.cscaKey)
        except OpenSSLException as msg:
            msg = str(msg)
            self._errorHandler(msg)
            self.getCrl()
        return self._openssl.crlToDER(crl)
    
    def _errorHandler(self, msg):
        if msg.find('newcerts')> 0:
            os.makedirs(os.path.join(self._loc, 'newcerts'))
            self.log("mkdir ca/newcerts")
        elif msg.find('ca/index.txt') > 0:
            self._openssl._toDisk(os.path.join(self._loc, 'index.txt'))
            self.log("touch ca/index.txt")
            self._openssl._toDisk(os.path.join(self._loc, 'index.txt.attr'), "unique_subject = no")
            self.log("echo 'unique_subject = no' > ca/index.txt.attr")
        elif msg.find('ca/serial') > 0:
            self._openssl._toDisk(os.path.join(self._loc, 'serial'), "01")
            self.log("echo '01' > ca/serial")
        elif msg.find('openssl.cfg') > 0:
            self._openssl._toDisk(self._configFile, self._getConfigFile(self._loc))
            self.log("Creation of ppenssl.cfg")
        else:
            raise OpenSSLException(msg)
        self.log(msg)
        
    def resetConfig(self):
        try:
            shutil.rmtree(self._loc)
        except:
            pass
        os.makedirs(os.path.join(self._loc, 'newcerts'))
        self._openssl._toDisk(os.path.join(self._loc, 'index.txt'))
        self._openssl._toDisk(os.path.join(self._loc, 'index.txt.attr'), "unique_subject = no")
        self._openssl._toDisk(os.path.join(self._loc, 'serial'), "01")
        self._openssl._toDisk(os.path.join(self._loc, 'crlnumber'), "01")
        self._openssl._toDisk(self._configFile, self._getConfigFile(self._loc))
        
    def _testinit(self):
        if not ((self.csca != None) and (self.cscaKey != None)):
            raise OpenSSLException("The root CSCA Certificate is not set.")
            
    def printCrl(self, crl):
        return self._openssl.printCrl(crl)

    def getCsca(self):
        return self._csca

    def getCscaKey(self):
        return self._cscaKey

    def setCsca(self, value):
        self._csca = value

    def setCscaKey(self, value):
        self._cscaKey = value
        
    csca = property(getCsca, setCsca, None, None)
    cscaKey = property(getCscaKey, setCscaKey, None, None)
    
    def _getConfigFile(self, path):
        
        altsep = os.altsep
        if not altsep:
            altsep = os.path.sep
        return  """# pour signer un certificat CA intermediaire
[ ca ]
default_ca     = CA_default           # The default ca section

[ CA_default ]
database       =     """+ os.path.join(self._loc, "index.txt").replace(os.path.sep, altsep) +"""       # database index file.
new_certs_dir  =     """+ os.path.join(self._loc, "newcerts").replace(os.path.sep, altsep) +"""       # default place for new certs.
crlnumber      =     """+ os.path.join(self._loc, "crlnumber").replace(os.path.sep, altsep) +"""
serial         =     """+ os.path.join(self._loc, "serial").replace(os.path.sep, altsep) +"""          # The current serial number
default_md     = sha1      # which md to use.

default_days    = 365
default_crl_days= 30

x509_extensions   = usr_cert
policy            = policy_match

[ req ]
distinguished_name  = req_distinguished_name
x509_extensions     = ca_cert

[ req_distinguished_name ]
#countryName            = Pays
#countryName_default    = BE

#organizationName         = Organisation
#organizationName_default = Gouv

#commonName         = Nom commun
#commonName_default = CSCA-BELGIUM

[ policy_match ]
countryName             = match
stateOrProvinceName     = optional
localityName            = optional
organizationName        = supplied
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ usr_cert ]
#These extensions are added when 'ca' signs a request.
basicConstraints        = CA:FALSE
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid
keyUsage                = critical, keyCertSign

[ ca_cert ]
# Extensions to add to a certificate request
basicConstraints       = critical, CA:true, pathlen:0
subjectKeyIdentifier   = hash
keyUsage               = critical, keyCertSign, cRLSign"""
        
        
#from pypassport.openssl import DistinguishedName, CA
#ca = CA()
#ca.resetConfig()
#dn = DistinguishedName(C="BE", O="UCL", CN="CSCA-BELGIUM")
#(csca, cscaKey) = ca.createCSCA(size=2048, dn=dn)
#(ds, dsKey) = ca.createDS()
#cscaCrl = ca.getCrl()
#dn = DistinguishedName(C="BE", O="bidon", CN="To revoke")
#(rev, revKey) = ca.createDS(dn=dn)
#ca.revoke(rev)
#revCrl = ca.getCrl()
