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

import os
from pypassport.hexfunctions import *
from pypassport.doc9303 import converter
from pypassport.doc9303 import datagroup
from hashlib import *
from pypassport.derobjectidentifier import *
import subprocess
from pypassport.logger import Logger
from pypassport.camanager import CAManager
from pypassport.openssl import OpenSSL, OpenSSLException
from pypassport.doc9303.datagroup import LDSSecurityObject

from pyasn1.type import univ, namedtype, namedval, constraint
from pyasn1.codec.der import encoder, decoder 

class PassiveAuthenticationException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class PassiveAuthentication(Logger):
    
    """ 
    This class implement the passive authentication protocol.
    The two main methods are I{verifySODandCDS} and I{executePA}. The first verify the SOD and the CDS and retrieve the relevant dataGroups
    from the LDS, that's why this method must be called before I{executePA} that uses these exctracted informations to calculate the hashes. 
    Even if the Certificate validation failed, it does not mean that the data could not been retrieved from the LDS. 
    """
    
    def __init__(self, openssl=None):
        Logger.__init__(self, "PA")
        self._content = None
        self._data = None
        if not openssl:
            self._openSSL = OpenSSL()
        else:
            self._openSSL = openssl
        
    def verifySODandCDS(self, sodObj, CSCADirectory):
        """ 
        Execute the first part of the Passive Authentication protocol.
            - Read the document signer from the Document Security Object
            - Verify SOD by using Document Signer Public Key (KPuDS). 
            - Verify CDS by using the Country Signing CA Public Key (KPuCSCA).
            - Read the relevant Data Groups from the LDS.  
            
        The I{toHash} method of the CSCADirectory object must be called before the passive authentication.
        Once the hashing processing is done, the I{toHash} method does not need to be called again.
            
        @param sodObj: An initialized security data object
        @type sodObj: An sod object
        @param CSCADirectory: The object representing the CSCA directory. 
        @type CSCADirectory: A CAManager object
        
        @return: True if the DS Certificate is valided
        
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object. 
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodobj parameter is a sod object, but is not initialized.
        @raise PassiveAuthenticationException: I{CSCADirectory is not set}
        @raise openSSLException: See the openssl documentation
        """
        
        if CSCADirectory == None:
            raise PassiveAuthenticationException("CSCADirectory is not set") 
        
        if type(sodObj) != type(datagroup.SOD(None)):
            raise PassiveAuthenticationException("sodObj must be a sod object")
        
        if type(CSCADirectory) != type(CAManager("")):
            raise PassiveAuthenticationException("CSCADirectory must be a CAManager object")
        
        CDS = self.getCertificate(sodObj)
        if CDS == None:
            #No certificate
            raise PassiveAuthenticationException("The certificate could not be retrieved")
        
        self._data = self.getSODContent(sodObj)
        
        self._content = self._readDGfromLDS(self._data)
        
        return self.verifyDSC(CDS, CSCADirectory.dir)
        
    def executePA(self, sodObj, dgs):
        """
        Execute the second part of the Passive Authentication protocol
            - Calculate the hashes of the given Data Groups. 
            - Compare the calculated hashes with the corresponding hash values in the SOD. 
            
        @param sodObj: An initialized security data object
        @type sodObj: An sod object
        @param dgs: A list of dataGroup objects to verify
        @type dgs: A list of dataGroup
        @return: The dictionnary is indexed with the DataGroup name (DG1...DG15) and the value is a boolean: True if the check is ok.
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object. 
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodobj parameter is a sod object, but is not initialized.
        @raise openSSLException: See the openssl documentation
        """
        
#        f = open("/home/jf/CA/sod", "wb")
#        f.write(sodObj.body)
#        f.close()
        
        if self._data == None:
            self._data = self.getSODContent(sodObj)
            
#        f = open("/home/jf/CA/sod_content", "wb")
#        f.write(self._data)
#        f.close()
        
        if self._content == None:
            self._content = self._readDGfromLDS(self._data)
            
        hashes = self._calculateHashes(dgs)
        return self._compareHashes(hashes)
        
    
    def getSODContent(self, sodObj):
        """
        Verify SOD by using Document Signer Public Key (KPuDS))
        
        @param sodObj: A filled SOD object
        @type sodObj: An SOD object  
        @return: The data (a binary string) if the verifucation is ok, else an PassiveAuthentication is raised.
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object. 
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodobj parameter is a sod object, but is not initialized.
        @raise openSSLException: See the openssl documentation
        """
        self.log("Verify SOD by using Document Signer Public Key (KPuDS))")
        
        if type(sodObj) != type(datagroup.SOD(None)):
            raise PassiveAuthenticationException("sodObj must be a sod object")
        
        if sodObj.body == None:
            raise PassiveAuthenticationException("sodObj object is not initialized")
        
        return self._openSSL.getPkcs7SignatureContent(sodObj.body)

    
    def verifyDSC(self, CDS, CSCADirectory):
        """ 
        Verify CDS by using the Country Signing CA Public Key (KPuCSCA).
        
        @param CDS: The document signer certificate
        @type CDS: A string formated in PEM
        @param CSCADirectory: The complete path to the directory where the CSCA are. The certificates must first be renamed with the corresponding hash. (See the CAManager.py)
        @type CSCADirectory: A string
        @return: True if the verification is ok
        @raise PassiveAuthenticationException: I{The CDS is not set}: The CDS parameter must be a non-empty string.
        @raise PassiveAuthenticationException: I{The CA is not set}: The CSCADirectory parameter must be a non-empty string.
        @raise openSSLException: See the openssl documentation
        """
        
        self.log("Verify CDS by using the Country Signing CA Public Key (KPuCSCA). ")
        
        if not CDS and type(CDS) == type(""):
            raise PassiveAuthenticationException("The CDS is not set")
        
        if not CSCADirectory and type(CSCADirectory) == type(""):
            raise PassiveAuthenticationException("The CA is not set")
        
        return self._openSSL.verifyX509Certificate(CDS, CSCADirectory)
        
    def getCertificate(self, sodObj):
        """  
        Retrieve de DocumentSiner certificate out of the SOD.
        @return: A PEM represenation of the certificate or None is not present.
        @raise PassiveAuthenticationException: I{sodObj must be a sod object}: the sodObj parameter must be a sod object. 
        @raise PassiveAuthenticationException: I{sodObj object is not initialized}: the sodobj parameter is a sod object, but is not initialized.
        @raise openSSLException: See the openssl documentation
        """
        if type(sodObj) != type(datagroup.SOD(None)):
            raise PassiveAuthenticationException("sodObj must be a sod object")
        
        if sodObj.body is None:
            raise PassiveAuthenticationException("sodObj object is not initialized")
        
        return self._openSSL.retrievePkcs7Certificate(sodObj.body)               
        
    def _readDGfromLDS(self, data):
        """
        Read the relevant Data Groups from the LDS
        
        @param data: The content of the verified signature.
        @type data:  A binary string
        @return: A dictionnary with the parsed data of the signature (version, hashAlgorithm and dataGrouphashValues)
        """
        self.log("Read the relevant Data Groups from the LDS")
        
        content = {}
        hash = {}
        
        certType = LDSSecurityObject()
        cert = decoder.decode(data, asn1Spec = certType)[0]
        
        content['version'] = cert.getComponentByName('version').prettyPrint()
        content['hashAlgorithm'] = cert.getComponentByName('hashAlgorithm').getComponentByName('algorithm').prettyPrint()
        
        for h in cert.getComponentByName('dataGroupHashValues'):
            hash[h.getComponentByName('dataGroupNumber').prettyPrint()] = h.getComponentByName('dataGroupHashValue')
        
        content['dataGroupHashValues'] = hash
        
        return content
        
    def _calculateHashes(self, dgs):
        """
        Calculate the hashes of the relevant Data Groups, theses presents in the signature.
        
        @param dgs: A list of dataGroup objects to calculate the hash values.
        @type dgs: A list.
        @return: A dictionnary indexed with DG1..DG15 with the calculated hashes of the DGs. 
        """
        self.log("Calculate the hashes of the relevant Data Groups")
        hashes = {}
        #Find the hash function from the content dictionary
        hashAlgo = self._getHashAlgorithm()
        for dg in dgs:
            res = hashAlgo(dg.file)
            hashes[converter.toDG(dg.tag)] = res.digest()
            
        return hashes
    
    def _compareHashes(self, hashes):
        """
        Compare the calculated hashes with the corresponding hashes present in the SOD.
        
        @param hashes: A dictionnary of hashes to compare with the security object hashes.
        @type hashes: A dictionary
        @return: A dictionnary indexed with the DG name (DG1..DG15) and with the result of the hash comparison (True or False, None if the DG is not present in the SOD)
        """
        self.log("Compare the calculated hashes with the corresponding hash values in the SOD")
        
        res = {}
        
        for dg in hashes:
            try:
                res[converter.toDG(dg)] = (hashes[dg] == self._content["dataGroupHashValues"][converter.toOther(dg)])
            except KeyError:
                res[converter.toDG(dg)] = None

        return res

    def _getHashAlgorithm(self):
        """
        Return the object corresponding to the hash algorithm used to calculate the hashes present in the SOD.
        @return: The object corresponding to the hash algorithm, or an oidException if not found.
        """
        if self._content is None:
            raise PassiveAuthenticationException("The object is not set. Call init first.")
        return self._getAlgoByOID(self._content['hashAlgorithm'])
    
    def _getAlgoByOID(self, oid):
        try:
            algo = OID[oid]
            return eval(algo)
        except KeyError:
            raise OIDException("No such algorithm for OID " + str(oid))
        
    def __str__(self):
        res =  "version: " + self._content["version"] + "\n"
        res += "hashAlgorithm: " + self._content["hashAlgorithm"] + "\n"
        res += "dataGroupHashValues: " + "\n"
        
        for dghv in list(self._content["dataGroupHashValues"].keys()):
            res += "dataGroupNumber: " + dghv + "\n"
            res += "dataGroupHashValue: " + binToHexRep(self._content["dataGroupHashValues"][dghv]) + "\n"

        return res
    
