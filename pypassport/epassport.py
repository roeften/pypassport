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


from pypassport.doc9303 import datagroup, passiveauthentication, activeauthentication, bac, converter, securemessaging, mrz, tagconverter
from pypassport import camanager
from pypassport import openssl
from pypassport import iso7816
from pypassport import logger
from pypassport import apdu
import os, traceback

class EPassportException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class EPassport(dict, logger.Logger):
    """ 
    This class is the high level class that encapsulate every mechanisms needed to communication with the passport
    and to validate it.
    
    This object is implemented as a dictionnary.
    When a dataGroup is read, the corresponding object is added inside the object dictionnary.

    Example with the DG1 file using the simulator:
    (see the dataGroups.converter for an exaustive convertion list)
    
    
    >>> import os
    >>> from pypassport.epassport import *
    >>> from pypassport.iso7816 import *
    >>> sep = os.path.sep
    >>> sim = "data" + sep + "dump" + sep + "test"
    >>> p = EPassport(None, sim)
    Select Passport Application
    >>> p["DG1"]
    Reading DG1
    {'5F05': '7', '5F04': '4', '5F07': '0', '5F06': '2', '59': '130312', '5F03': 'P<', '5F02': '0', '5F5B': 'ROGER<<OLIVIER<VINCENT<MICHAEL<<<<<<<<<', '5F1F': 'P<BELROGER<<OLIVIER<VINCENT<MICHAEL<<<<<<<<<AB123456<4BEL9503157M1303122<<<<<<<<<<<<<<00', '53': '<<<<<<<<<<<<<<', '5F2C': 'BEL', '5F57': '950315', '5F28': 'BEL', '5F35': 'M', '5A': 'AB123456<'}
    >>> p["61"]
    {'5F05': '7', '5F04': '4', '5F07': '0', '5F06': '2', '59': '130312', '5F03': 'P<', '5F02': '0', '5F5B': 'ROGER<<OLIVIER<VINCENT<MICHAEL<<<<<<<<<', '5F1F': 'P<BELROGER<<OLIVIER<VINCENT<MICHAEL<<<<<<<<<AB123456<4BEL9503157M1303122<<<<<<<<<<<<<<00', '53': '<<<<<<<<<<<<<<', '5F2C': 'BEL', '5F57': '950315', '5F28': 'BEL', '5F35': 'M', '5A': 'AB123456<'}
    
    
    You can notice than the DG1 is read only during the first call.
    
    The passport application is selected during the init phase, 
    and the basic access control is done automatically if needed.
    
    Example with the using an rfid reader:
    *Detect the reader
    *Init the EPassport class
    *Read the DG1
    *Perform Active Auth
    *Perform Passive Auth (Verification of the SOD Certificate, Verification of the DG integrity)
    *Extract the DS Certificate
    *Extract the DG15 public key
    *Extract the faces from DG2
    *Extract the signature from DG7
    
    (The informations are hidded)
    
    We changed the MRZ informations for privacy reasons, that's why the doctest is not valid.
    Anyway it is not possible for you to test it without the real passport (you do not possess it).
    Just consider it as a trace explaining how to access a real passport.
    
    
    >>> from pypassport.epassport import EPassport, mrz
    >>> from pypassport.reader import pcscAutoDetect
    >>> from pypassport.openssl import OpenSSLException
    >>> detect = pcscAutoDetect()
    >>> detect
    (<pypassport.reader.pcscReader object at 0x00CA46F0>, 1, 'OMNIKEY CardMan 5x21-CL 0', 'GENERIC')
    >>> reader = detect[0]
    >>> mrz = mrz.MRZ('EHxxxxxx<0BELxxxxxx8Mxxxxxx7<<<<<<<<<<<<<<04')
    >>> mrz.checkMRZ()
    True
    >>> p = EPassport(mrz, reader)
    Select Passport Application
    >>> p["DG1"]
    Reading DG1
    {'5F05': '8', '5F04': '0', '5F07': '4', '5F06': '7', '59': '130221', '5F03': 'P<
    ', '5F02': '0', '5F5B': 'ROGER<<OLIVIER<VINCENT<MICHAEL<<<<<<<<<', '5F1F': 'P<BE
    LROGER<<OLIVIER<VINCENT<MICHAEL<<<<<<<<<EHxxxxx<0BELxxxxxx8Mxxxxxx7<<<<<<<<<<<<<<04', '53': '<<<<<<<<<<<<<<', '5F2C': 'BEL', '5F57': '840615', '5F28': 'BEL', '5F35': 'M', '5A': 'EH276509<'}
    >>> p.openSslDirectory = "C:\\OpenSSL\\bin\\openssl"
    >>> p.doActiveAuthentication()
    Reading DG15
    Active Authentication: True
    True
    >>> p.CSCADirectory = 'D:\\workspace\\pypassport\\src\data\\cert'
    >>> try:
    ...     p.doVerifySODCertificate()
    ... except OpenSSLException, msg:
    ...     print msg
    ...
    /C=BE/O=Kingdom of Belgium/OU=Federal Public Service Foreign Affairs Belgium/CN=DSPKI_BEerror 20 at 0 depth lookup:unable to get local issuer certificate
    >>> try:
    ...     p.doVerifyDGIntegrity()
    ... except pypassport.openssl.OpenSSLException, msg:
    ...     print msg
    ...
    Reading Common
    Reading DG2
    Reading DG7
    Reading DG11
    Reading DG12
    {'DG15': True, 'DG11': True, 'DG12': True, 'DG2': True, 'DG1': True, 'DG7': True}
    >>> p.getCertificate()
    'subject=/C=BE/O=Kingdom of Belgium/OU=Feder...eign Affairs Belgium/CN=CSCAPKI_BE
    -----BEGIN CERTIFICATE-----
    MIIEnDCCAoSgA...IJhypc0=
    -----END CERTIFICATE-----'
    >>> p.getPublicKey()
    'Modulus=D8772AC284BE...8FC508B57AFBD57
    -----BEGIN PUBLIC KEY-----
    MIGdMA0GCSqGSIb3DQEBAQUAA...ck4/FCLV6+9VwIBAw==
    -----END PUBLIC KEY-----'
    >>> p.getFaces()
    ['\x14R\x06\x14\xd3E\x14\xfa\x87C\xff\xd9...']
    >>> p.getSignature()
    ['\x01h\xa4\xa2...\x80?\xff\xd9']
    
    
    """
    #TODO: property pr le buffSize de la lecture et pour choisir si FS ou SFID
    def __init__(self, reader, epMrz=None):
        """ 
        This object provide most of the functionnalities described in the EPassport document.
            - The basic acces control + secure messaging
            - The active authentication
            - The passive authentication
            - Reading of the various dataGroups
        
        @param reader: It can be a reader or a path to dumps
        @type reader: A reader object, then it will use the specified rfid reader. 
                      A string, then the simulator will read the dumps from the specified url.  
        
        @param mrz: An object representing the passport MRZ.
        @type mrz: An MRZ object 
        """
        logger.Logger.__init__(self, "EPassport")
        
        if epMrz:
            self._mrz = mrz.MRZ(epMrz)
            if self._mrz.checkMRZ() == False:
                raise EPassportException("Invalid MRZ")
        else: self._mrz = None
        
        self._iso7816 = iso7816.Iso7816(reader)
        self._iso7816.register(self._logFct)
        
        self._dgReader = datagroup.DataGroupReaderFactory().create(self._iso7816)
        self._dgReader.register(self._logFct)
        
        self._bac = bac.BAC(self._iso7816)
        self._bac.register(self._logFct)
        
        self._openSSL = openssl.OpenSSL()
        self._openSSL.register(self._logFct)
        
        self._aa = activeauthentication.ActiveAuthentication(self._iso7816, self._openSSL)
        self._aa.register(self._logFct)
        
        self._pa = passiveauthentication.PassiveAuthentication(self._openSSL)
        self._pa.register(self._logFct)
        
        self._CSCADirectory = None
        self._selectPassportApp()

    def _getOpenSslDirectory(self):
        return self._openSSL.location

    def _setOpenSslDirectory(self, value):
        self._openSSL.location = value
        
    def getCSCADirectory(self):
        return self._CSCADirectory

    def setCSCADirectory(self, value, hash=False):
        self._CSCADirectory = camanager.CAManager(value)
        if hash:
            self.log("Document Signer Certificate hash creation")
            self._CSCADirectory.toHashes()
        
    def getCommunicationLayer(self):
        return self._iso7816
    
    def _isSecureMessaging(self):
        return self._reader.isSecured()
    
    def _selectPassportApp(self):
        """
        Select the passport application
        """
        self.log("Select Passport Application")
        return self._iso7816.selectFile("04", "0C", "A0000002471001")
    
    def doBasicAccessControl(self):
        """
        Execute the basic acces control protocol and set up the secure messaging.
        
        @return: A True if the BAC execute correctly
        @raise bacException: If an error occur during the process
        @raise EPassportException: If the mrz is not initialized.
        """
        if self._mrz == None:
            raise EPassportException("The object must be initialized with the ePassport MRZ")
        
        (KSenc, KSmac, ssc) = self._bac.authenticationAndEstablishmentOfSessionKeys(self._mrz)
        sm = securemessaging.SecureMessaging(KSenc, KSmac, ssc) 
        sm.register(self._logFct)
        return self._iso7816.setCiphering(sm)
               
    def doActiveAuthentication(self, dg15=None):
        """
        Execute the active authentication protocol.
        
        @return: A boolean if the test complete.
        @raise aaException: If the hash algo is not supported or if the AA is not supported.
        @raise openSSLException: See the openssl documentation
        @raise SimIso7816Exception: The AA is not possible with the simulator
        """
        res = ""
        try:
            if dg15 == None:
                dg15 = self["DG15"]
            res = self._aa.executeAA(dg15)
            return res
        except datagroup.DataGroupException as msg:
            res = msg
            raise DataGroupException(msg)
        except openssl.OpenSSLException as msg:
            res = msg
            raise openssl.OpenSSLException(msg)
        except Exception as msg:
            res = msg
            raise activeauthentication.ActiveAuthenticationException(msg)
        finally:
            self.log("Active Authentication: " + str(res))
    
    def doVerifySODCertificate(self):
        """  
        Execute the first part of the passive authentication: The verification of the certificate validity.
        
        @raise dgException: If the SOD could not be read
        @raise paException: If the object is badly configured
        @raise openSSLException: See the openssl documentation 
        """
        res = ""
        try:
            sod = self.readSod()
            res = self._pa.verifySODandCDS(sod, self.CSCADirectory)
            return res
        except datagroup.DataGroupException as msg:
            res = msg
            raise datagroup.DataGroupException(msg)
        except passiveauthentication.PassiveAuthenticationException as msg:
            res = msg
            raise passiveauthentication.PassiveAuthenticationException(msg)
        except openssl.OpenSSLException as msg:
            res = msg
            raise openssl.OpenSSLException(msg)
        finally:
            self.log("Document Signer Certificate verification: " + str(res))
        
    def doVerifyDGIntegrity(self, dgs=None):
        """  
        Execute the second part of the passive authentication: The verification of the dataGroups integrity.
        
        @raise dgException: If the data groups could not be read
        @raise paException: If the object is badly configured
        @raise openSSLException: See the openssl documentation 
        """
        res = None
        try:
            sod = self.readSod()
            if dgs == None:
                dgs = self.readDataGroups()
            res = self._pa.executePA(sod, dgs)
            return res
        except datagroup.DataGroupException as msg:
            res = msg
            raise datagroup.DataGroupException(msg)
        except passiveauthentication.PassiveAuthenticationException as msg:
            res = msg
            raise passiveauthentication.PassiveAuthenticationException(msg)
        except openssl.OpenSSLException as msg:
            res = msg
            raise openssl.OpenSSLException(msg)
        except Exception as msg:
        	res = msg
        finally:
            self.log("Data Groups integrity verification: " + str(res))
            
    
    def readSod(self):
        """
        Read the security object file of the passport.
        
        @return: A sod object.
        """
        return self["SecurityData"]
    
    def readCom(self):
        """
        Read the common file of the passport.
        
        @return: A list with the data group tags present in the passport. 
        """
        list = []
        for tag in self["Common"]["5C"]:
            list.append(converter.toDG(tag))
        return list
            
    def readDataGroups(self):
        """
        Read the datagroups present in the passport. (DG1..DG15)
        The common and sod files are not read.
        
        @return: A list of dataGroup objects.
        """
        list = []
        for dg in self["Common"]["5C"]:
            list.append(self[dg])
        return list
            
    def readPassport(self):
        """
        Read every files of the passport (COM, DG1..DG15, SOD)
        
        @return: A dictionnary with every dataGroup objects present in the passport.
        """
        self.log("Reading Passport")
        self.readCom()
        self.readDataGroups()
        self.readSod()
        
        return self
        
    #Dict overwriting
    def __getitem__(self, tag):
        """
        @param tag: A Valid tag representing a dataGroup
        @type tag: A string
        @return: The datagroup object representing this dataGroup

        @raise DataGroupException: If the tag is not linked to any dataGroup, or if an error occurs during the parsing
        @raise APDUException: If an error occurs during the APDU transmit.
            
        Try to read the DataGroup specified by the parameter 'tag'.
        If the DG is already read, the DG is directly returned, 
        else the DG is read then returned
        
        If there is a Security status not satisfied error, 
        the mutual authentication is run. 
        If there is no error during the mutualAuth, the APDU is resend else,
        the error is propagated: there surely is an error in the MRZ field value
        
        Please refer to ICAO Doc9303 Part 1 Volume 2, p III-28 for the complete 
        DataGroup <-> Tag correspondance 
        or have a look to the pypassport.datagroup.converter.py file       
        """
        self.log("getitem " + tag)
        tag = converter.toTAG(tag)
        self.log("getitem converted " + tag)
        if tag not in self:
            try:
                tag = converter.toTAG(tag)
                return self._getDG(tag)
            except iso7816.Iso7816Exception as exc:
                if exc[1] == 105 and exc[2] == 130:
                    #Security status not satisfied
                    self.log("Enabling Secure Messaging")
                    self.doBasicAccessControl()
                    return self._getDG(tag)
                else: 
                    raise datagroup.DataGroupException(str(exc))
            except KeyError:
                raise datagroup.DataGroupException("The data group '" + str(tag) + "' does not exist")
            except Exception as msg:
                self.log(msg)
                traceback.print_exc()
        else:
            return super(EPassport, self).__getitem__(tag)
    
    def _getDG(self, tag):
        """ 
        Read the dataGroup file specified by the parameter 'tag', then try to parse it.
        The dataGroup object is then stored in the object dictionnary.
        
        
        @param tag: The dataGroup identifier to read (see the dataGroups.converter for all valid representations)
        @type tag: A string
        
        @return: An dataGroup object if the file is read with success.
        @rtype: An DataGroupXX object
        
        @raise DataGroupException: If a wrong DataGroup is requested
        """
        try:
            self.log("Reading " + converter.toDG(tag))
            dgFile = self._dgReader.readDG(tag)
            self.log("File " + str(dgFile))
            dg = datagroup.DataGroupFactory().create(dgFile)
            self.log("DG " + str(dg))
            self.__setitem__(dg.tag, dg) 
            return dg
        except IOError as msg:
            self.log("Reading error: " + str(msg))
            raise datagroup.DataGroupException(msg)
        
    
    def stopReading(self):
        self._dgReader.stop = True
    
    def __iter__(self):
        """ 
        Implementation of the object iterator method.
        Read every passport files.
        """
        self.readPassport()
        return super(EPassport, self).__iter__()
        
    def getSignatures(self):
        """
        Return a list with the signatures contained in the DG7 in binary format.
        @return: A list of binary string
        @rtype: A list
        """
        tmp = []
        try:
            dg7 = self["DG7"]
            
            for tag in ["5F43"]:
                if tag in dg7:
                    for x in dg7[tag]:
                        tmp.append(x)
                        
        except Exception:
            pass
        return tmp
            
    def getFaces(self):
        """
        Return a list with the images contained in the DG2 in binary format.
        @return: A list of binary string
        @rtype: A list
        """
        dg2 = self["DG2"]
        tmp = []
        try:
            cpt=1
            for A in dg2:
                self.log("DG2 " + A)
                if A == "A" + str(cpt):
                    cpt += 1
                    for tag in ["5F2E", "7F2E"]:
                        if tag in dg2[A]:
                            tmp.append(dg2[A][tag])
        except:
            pass
                
        return tmp    
    
    def getCertificate(self):
        """  
        Extract the Document Signer certificate from the SOD
        @return: The certificate in a human readable format
        @rtype: A string
        """
        try:
            return self._pa.getCertificate(self.readSod())
        except Exception:
            return None
    
    def getPublicKey(self):
        """  
        Extract the Active Auth public key from the DG15
        @return: The public key in a human readable format
        @rtype: A string
        """
        try:
            return self._aa.getPubKey(self["DG15"])
        except Exception:
            return None
        
    def dump(self, directory=os.path.expanduser('~'), format=converter.types.GRT, extension = ".bin"):
        """ 
        Dump the ePassport content on disk as well ass the faces ans signatures in jpeg,
        the DG15 public key and the Document Signer Certificate.
        
        By default, the files are stored in the user directory (~) with the Golden Reader Tool naming format
        
        @param directory: The taget directory
        @param format: File naming format (see the convertion module)
        @param extension: File extension
        """
        dgd = datagroup.DataGroupDump(directory, extension)
        dgd.dump(self, format)
        
        cpt=0
        for sig in self.getSignatures():
            dgd.dumpData(sig, "signature" + str(cpt) + ".jpg")
            cpt += 1
            
        cpt=0
        for face in self.getFaces():
            dgd.dumpData(face, "face" + str(cpt) + ".jpg")
            cpt += 1
        
        dgd.dumpData(self.getPublicKey(), "DG15PubKey.pk")
        dgd.dumpData(self.getCertificate(), "DocumentSigner.cer")
        
    def _logFct(self, name, msg):
        self.log(msg, name)
        
    CSCADirectory = property(getCSCADirectory, setCSCADirectory)
    isSecureMessaging = property(_isSecureMessaging)
    openSsl = property(_getOpenSslDirectory, _setOpenSslDirectory, None, None)
    
if __name__ == "__main__":
    import doctest
    doctest.testmod()
