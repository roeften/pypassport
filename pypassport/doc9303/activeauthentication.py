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
from hashlib import *
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype,univ
from pypassport.asn1 import *

from pypassport.hexfunctions import *
from pypassport.derobjectidentifier import *
from pypassport.logger import Logger
from pypassport.openssl import OpenSSL, OpenSSLException
from pypassport.doc9303 import datagroup

class ActiveAuthenticationException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)
        
class ActiveAuthentication(Logger):
    """  
    This class implement the Active Authentication protocol.
    The main method is I{executeAA} that return True is the verification is ok or False.
    """
    def __init__(self, iso7816, openssl=None):
        """
        @param iso7816: a valid iso7816 object
        @type iso7816: doc9303  
        """
        Logger.__init__(self, "AA")
        self._iso7816 = iso7816
        if not openssl:
            self._openssl = OpenSSL()
        else:
            self._openssl = openssl
        self._openssl.register(self.log)    
        self.RND_IFD = None
        self.F = None
        self.T = None
        self.decryptedSignature = None
        self.D = None
        self.D_ = None
        self.M1 = None
        self.M_ = None
        
        self._dg15 = None
        
    def executeAA(self, dg15): 
        """
        Perform the Active Authentication protocol.
        Work only with RSA, modulus length of 1024 and with SHA1.
        
        @param dg15: A initialized dataGroup15 object
        @type dg15: dataGroup15 
        @return: True if the authentication succeed, else False.
        @rtype: Boolean
        @raise ActiveAuthenticationException: If the Active Authentication is not supported (The DG15 is not found or the hash algo is not supported). 
        @raise ActiveAuthenticationException: If the parameter is not set or invalid.
        @raise ActiveAuthenticationException: If OpenSSL is not installed.
        @raise ActiveAuthenticationException: If the public key cannot be recovered from the DG15.
        @raise ActiveAuthenticationException: If the DG15 is invalid and the signature cannot be verified.
        """
        self._dg15 = dg15
        
        self.RND_IFD = self._genRandom(8)
        self.signature = self._getSignature(self.RND_IFD)
        self.F = self._decryptSignature(dg15.body, self.signature)
        
        (hash, hashSize, offset) = self._getHashAlgo(self.F)
        self.D = self._extractDigest(self.F, hashSize, offset)
        self.M1 = self._extractM1(self.F, hashSize, offset)
        
        self.M_ = self.M1 + self.RND_IFD
        
        self.log("Concatenate M1 with known M2")
        self.log("\tM*: " + binToHexRep(self.M_))
        
        self.D_ = self._hash(hash, self.M_)

        self.log("Compare D and D*")
        self.log("\t" + str(self.D == self.D_))
        
        return self.D == self.D_
    
    def _genRandom(self, size):
        rnd_ifd = os.urandom(size)
        self.log("Generate an 8 byte random")
        self.log("\tRND.IFD: " + binToHexRep(rnd_ifd))
        return rnd_ifd
        
    def _getSignature(self, rnd_ifd):
        return self._iso7816.internalAuthentication(rnd_ifd)
        
    def getPubKey(self, dg15):
        """  
        Retrieve the public key in PEM format from the dataGroup15
        
        @return: A PEM reprensation of the public key
        @rtype: A string
        @raise ActiveAuthenticationException: I{The parameter type is not valid, must be a dataGroup15 object}: The parameter dg15 is not set or invalid.
        @raise ActiveAuthenticationException: I{The public key could not be recovered from the DG15}: Is open SSL installed?
        """
        
        if type(dg15) != type(datagroup.DataGroup15(None)):
            raise ActiveAuthenticationException("The parameter type is not valid, must be a dataGroup15 object")
        
        return self._openssl.retrieveRsaPubKey(dg15.body)
        
    def _decryptSignature(self, pubK, signature):

        data = self._openssl.retrieveSignedData(pubK, signature)
        self.log("Decrypt the signature with the public key")
        self.log("\tF: " + binToHexRep(data))
        
        return data
        
    def _hash(self, hash, data):
        digest = hash(data).digest()
        
        self.log("Calculate digest of M*")
        self.log("\tD*: " + binToHexRep(digest))
        
        return digest
        
    def _getHashAlgo(self, sig):
        hash = None
        offset = None
        hashSize = None
        
        if sig[-1] == 0xBC:
            self.T = sig[-1]
            hash = sha1
            offset = -1
        elif sig[-1] == 0xCC:
            self.T = sig[-2]
            #hash = The algorithm corresponding to the algo designed by T
            offset = -2
        else:
            raise ActiveAuthenticationException("Unknow hash algorithm")
        
        self.log("Determine hash algorithm by trailer T*")
        self.log("\tT: " + binToHexRep(self.T))
                
        #Find out the hash size
        hashSize = len(hash(b"test").digest())
    
        return (hash, hashSize, offset)
    
    def _extractDigest(self, sig, hashSize, offset):
        digest = sig[offset - hashSize:offset]
        
        self.log("Extract digest:")
        self.log("\tD: " + binToHexRep(digest))
        
        return digest
    
    def _extractM1(self, sig, hashSize, offset):
        M1 = sig[1:offset - hashSize]
        
        self.log("Extract M1:")
        self.log("\tM1: " + binToHexRep(M1))
        
        return M1
    
    def __str__(self):
        spec = self._asn1Parse()
        return spec.prettyPrint()
    
    def algorithm(self, dg15):
        """
        Return the algorithm name used to store the signature
        @return: A string from the OID dictionnary.
        @raise ActiveAuthenticationException: I{Unsupported algorithm}: The algorithm does not exist in the OID enumeration.
        @raise ActiveAuthenticationException: I{The parameter type is not valid, must be a dataGroup15 object}: The parameter dg15 is not set or invalid.
        """
        if type(dg15) != type(datagroup.DataGroup15(None)):
            raise ActiveAuthenticationException("The parameter type is not valid, must be a dataGroup15 object")
        algo = ""
        try:
            spec = self._asn1Parse()
            algo = spec.getComponentByName('algorithm').getComponentByName('algorithm').prettyPrint()
            return OID[algo]
        except KeyError:
            raise ActiveAuthenticationException("Unsupported algorithm: " + algo)
        except Exception as msg:
            raise ActiveAuthenticationException("Active Authentication not supported: ", msg)

    def _asn1Parse(self):
        if self._dg15 != None:
            certType = SubjectPublicKeyInfo()
            return decoder.decode( self._dg15.body, asn1Spec = certType)[0]
        return ""

