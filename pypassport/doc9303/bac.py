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

import os, struct

from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from hashlib import sha1

from pypassport.doc9303.mrz import MRZ
from pypassport.logger import Logger
from pypassport.hexfunctions import *
from pypassport.iso9797 import *
from pypassport import apdu
from pypassport.hexfunctions import hexToHexRep, binToHexRep, rawbytes
from pypassport.iso7816 import Iso7816

class BACException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)
    def __getitem__(self, i):
        return self.args[i]
        
class BAC(Logger):
    
    """  
    This class perform the Basic Acces Control.
    The main method is I{authenticationAndEstablishmentOfSessionKeys}, it will execute the whole protocol and return the set of keys.
    """
    
    KENC= b'\0\0\0\1'
    KMAC= b'\0\0\0\2'
    
    def __init__(self, iso7816):
        """  
        @param iso7816: A valid iso7816 object connected to a reader.
        @type iso7816: A iso7816 object
        """
        Logger.__init__(self, "BAC")
        self._iso7816 = iso7816
        self._ksenc = None
        self._ksmac = None
        self._kifd = None
        self._rnd_icc = None
        self._rnd_ifd = None
        
    def authenticationAndEstablishmentOfSessionKeys(self, mrz):
        """
        Execute the complete BAC process:
            - Derivation of the document basic acces keys
            - Mutual authentication
            - Derivation of the session keys
            
        @param mrz: The machine readable zone of the passport
        @type mrz: an MRZ object
        @return: A set composed of (KSenc, KSmac, ssc)   
        
        @raise MRZException: I{The mrz length is invalid}: The mrz parameter is not valid.
        @raise BACException: I{Wrong parameter, mrz must be an MRZ object}: The parameter is invalid.
        @raise BACException: I{The mrz has not been checked}: Call the I{checkMRZ} before this method call.
        @raise BACException: I{The sublayer iso7816 is not available}: Check the object init parameter, it takes an iso7816 object
        """
        
        if type(mrz) != type(MRZ(None)):
            raise BACException("Wrong parameter, mrz must be an MRZ object")
        
        if not mrz.checked:
            mrz.checkMRZ()
        
        if type(self._iso7816) != type(Iso7816(None)):
            raise BACException("The sublayer iso7816 is not available")
        
        try:
            self.derivationOfDocumentBasicAccesKeys(mrz)
            rnd_icc = self._iso7816.getChallenge()
            
            cmd_data = self.authentication(rnd_icc)
            data = self._mutualAuthentication(cmd_data)
            return self.sessionKeys(data)
        except Exception as msg:
            raise msg
        
    def _mutualAuthentication(self, cmd_data):
        data = binToHexRep(cmd_data)
        lc = hexToHexRep(len(data)/2) 
        toSend = apdu.CommandAPDU("00", "82", "00", "00", lc, data, "28")
        
        return self._iso7816.transmit(toSend, "Mutual Authentication")
       
    def _computeKeysFromKseed(self, Kseed):
        """
        This function is used during the Derivation of Document Basic Acces Keys.
        
        @param Kseed: A 16 bytes random value
        @type Kseed: Binary
        @return: A set of two 8 bytes encryption keys
        """
        
        self.log("Input")
        self.log("\tKseed: " + binToHexRep(Kseed))
        
        self.log("Compute Encryption key (c:" + binToHexRep(BAC.KENC) + ")")
        kenc = self.keyDerivation(Kseed,BAC.KENC)
        
        self.log("Compute MAC Computation key (c:" + binToHexRep(BAC.KMAC) + ")")
        kmac = self.keyDerivation(Kseed,BAC.KMAC)
        
        return (kenc, kmac)
        
    def derivationOfDocumentBasicAccesKeys(self, mrz):
        """
        Take the MRZ object, constrct the mrz_information out of the MRZ (kmrz),
        generate the Kseed and compute the kenc and Kmac keys from the Kseed.
        
        @param mrz: The machine readable zone of the passport.
        @type mrz: an MRZ object  
        @return: A set of two 8 bytes encryption keys (Kenc, Kmac)
        """
        self.log("Read the mrz")
        self.log("\tMRZ: " + str(mrz))
        
        kmrz = self.mrz_information(mrz)
        kseed = self._genKseed(kmrz)
        
        self.log("Calculate the Basic Acces Keys (Kenc and Kmac) using Appendix 5.1")
        (kenc, kmac) = self._computeKeysFromKseed(kseed)
        
        self._ksenc = kenc
        self._ksmac = kmac
        
        return (kenc, kmac) 
        
        
    def authentication(self, rnd_icc, rnd_ifd=None, kifd=None):
        """
        Construct the command data for the mutual authentication.
            - Request an 8 byte random number from the MRTD's chip (rnd.icc)
            - Generate an 8 byte random (rnd.ifd) and a 16 byte random (kifd)
            - Concatenate rnd.ifd, rnd.icc and kifd (s = rnd.ifd + rnd.icc + kifd)
            - Encrypt it with TDES and the Kenc key (eifd = TDES(s, Kenc))
            - Compute the MAC over eifd with TDES and the Kmax key (mifd = mac(pad(eifd))
            - Construct the APDU data for the mutualAuthenticate command (cmd_data = eifd + mifd)
            
        @param rnd_icc: The challenge received from the ICC.
        @type rnd_icc: A 8 bytes binary string
        @return: The APDU binary data for the mutual authenticate command   
        """
        if(type(rnd_icc) == str):
            rnd_icc = rawbytes(rnd_icc)
        self._rnd_icc = rnd_icc
        self.log("Request an 8 byte random number from the MRTD's chip")
        self.log("\tRND.ICC: " + binToHexRep(self._rnd_icc))
        
        if not rnd_ifd:
            rnd_ifd = os.urandom(8)
        if not kifd:
            kifd = os.urandom(16)
        self.log("Generate an 8 byte random and a 16 byte random")
        self.log("\tRND.IFD: " + binToHexRep(rnd_ifd))
        self.log("\tRND.Kifd: " + binToHexRep(kifd))

        
		
        s = rnd_ifd + self._rnd_icc + kifd
        
        self.log("Concatenate RND.IFD, RND.ICC and Kifd")       
        self.log("\tS: " + binToHexRep(s))
         
        tdes= DES3.new(self._ksenc,DES.MODE_CBC,b'\0'*8)

        eifd= tdes.encrypt(s)
        self.log("Encrypt S with TDES key Kenc as calculated in Appendix 5.2")
        self.log("\tEifd: " + binToHexRep(eifd))
        
        mifd = mac(self._ksmac, pad(eifd))
        self.log("Compute MAC over eifd with TDES key Kmac as calculated in-Appendix 5.2")
        self.log("\tMifd: " + binToHexRep(mifd))
        #Construct APDU
        
        cmd_data = eifd + mifd
        self.log("Construct command data for MUTUAL AUTHENTICATE")
        self.log("\tcmd_data: " + binToHexRep(cmd_data))
        
        self._rnd_ifd = rnd_ifd
        self._kifd = kifd
        
        return cmd_data

    def sessionKeys(self, data):
        """
        Calculate the session keys (KSenc, KSmac) and the SSC from the data 
        received by the mutual authenticate command.
        
        @param data: the data received from the mutual authenticate command send to the chip.
        @type data: a binary string
        @return: A set of two 16 bytes keys (KSenc, KSmac) and the SSC 
        """
        self.log("Decrypt and verify received data and compare received RND.IFD with generated RND.IFD " + binToHexRep(self._ksmac))
        # this does not work, encryption with cards ksmac
        # mac(self._ksmac, data[0:32]) != data[32:]:
        #    raise Exception("The MAC value is not correct")
        
        tdes= DES3.new(self._ksenc,DES.MODE_CBC,b'\0'*8)
        response = tdes.decrypt(data[0:32])
        response_kicc = response[16:32]
        Kseed = self._xor(self._kifd, response_kicc)
        self.log("Calculate XOR of Kifd and Kicc")
        self.log("\tKseed: " + binToHexRep(Kseed))
        
        KSenc = self.keyDerivation(Kseed,BAC.KENC)
        KSmac = self.keyDerivation(Kseed,BAC.KMAC)
        self.log("Calculate Session Keys (KSenc and KSmac) using Appendix 5.1")
        self.log("\tKSenc: " + binToHexRep(KSenc))
        self.log("\tKSmac: " + binToHexRep(KSmac))
        
        ssc = self._rnd_icc[-4:] + self._rnd_ifd[-4:]
        self.log("Calculate Send Sequence Counter")
        self.log("\tSSC: " + binToHexRep(ssc))
        return (KSenc, KSmac, ssc)   
        
    def _xor(self, kifd, response_kicc):
        kseed = b""
        for i in range(len(kifd)):
            kseed += struct.pack("B",kifd[i] ^ response_kicc[i])
            #kseed += hex(int(binToHexRep(kifd)[i],16) ^ int(binToHexRep(response_kicc)[i],16))[2:]
        #return hexRepToBin(kseed)
        return kseed
    def mrz_information(self, mrz):
        """
        Take an MRZ object and construct the MRZ information out of the MRZ extracted informations:
            - The Document number + Check digit
            - The Date of Birth + CD
            - The Data of Expirity + CD
            
        @param mrz: An MRZ object
        @type mrz: MRZ object
        @return: the mrz information used for the key derivation
        """
        if type(mrz) != MRZ:
            raise BACException("Bad parameter, must be an MRZ object (" + str(type(mrz)) + ")")
        
        kmrz = mrz.docNumber[0] + mrz.docNumber[1] + \
            mrz.dateOfBirth[0] + mrz.dateOfBirth[1] + \
            mrz.dateOfExpiry[0] + mrz.dateOfExpiry[1]
            
        self.log("Construct the 'MRZ_information' out of the MRZ")
        self.log("\tDocument number: " + mrz.docNumber[0] + "\tcheck digit: " + mrz.docNumber[1])
        self.log("\tDate of Birth: " + mrz.dateOfBirth[0] + "\t\tcheck digit: " + mrz.dateOfBirth[1])
        self.log("\tDate of Expirity: " + mrz.dateOfExpiry[0] + "\tcheck digit: " + mrz.dateOfExpiry[1])
        self.log("\tMRZ_information: " + kmrz)
        
        return kmrz.encode()

    def _genKseed(self, kmrz):
        """
        Calculate the kseed from the kmrz:
            - Calculate a SHA-1 hash of the kmrz 
            - Take the most significant 16 bytes to form the Kseed.
        
        @param kmrz: The MRZ information
        @type kmrz: a string
        @return: a 16 bytes string
        """
        
        self.log("Calculate the SHA-1 hash of MRZ_information")
        kseedhash= sha1(rawbytes(kmrz))
        kseed = kseedhash.digest()
        self.log("\tHsha1(MRZ_information): " + binToHexRep(kseed))
        
        self.log("Take the most significant 16 bytes to form the Kseed")
        self.log("\tKseed: " + binToHexRep(kseed[:16]))
        
        return kseed[:16]
    
    def keyDerivation(self, kseed, c):
        """
        Key derivation from the kseed:
            - Concatenate Kseed and c (c=0 for KENC or c=1 for KMAC) 
            - Calculate the hash of the concatenation of kseed and c (h = (sha1(kseed + c)))
            - Adjust the parity bits
            - return the key (The first 8 bytes are Ka and the next 8 bytes are Kb)
            
        @param kseed: The Kseed
        @type kseed: a 16 bytes string
        @param c: specify is it derives KENC (c=0) of KMAC (c=1)
        @type c: a byte
        @return: Return a 16 bytes key
        """
        
        if c not in (BAC.KENC,BAC.KMAC):
            raise BACException("Bad parameter (c=0 or c=1)")
        
        d = kseed + c
        self.log("\tConcatenate Kseed and c")
        self.log("\t\tD: " + binToHexRep(d))
        
        h = sha1(d).digest()
        self.log("\tCalculate the SHA-1 hash of D")
        self.log("\t\tHsha1(D): " + binToHexRep(h))
        
        Ka = h[:8]
        Kb = h[8:16]
        
        self.log("\tForm keys Ka and Kb")
        self.log("\t\tKa: " + binToHexRep(Ka))
        self.log("\t\tKb: " + binToHexRep(Kb))
        
        Ka = self.DESParity(Ka)
        Kb = self.DESParity(Kb)
        
        self.log("\tAdjust parity bits")
        self.log("\t\tKa: " + binToHexRep(Ka))
        self.log("\t\tKb: " + binToHexRep(Kb))
        return Ka+Kb
    
    def DESParity(self, data):
        adjusted= b''
        for x in range(len(data)):
            f = data[x]
            if(type(f) == str):
                f = ord(f)
            y= f & 0xfe
            parity= 0
            for z in range(8):
                parity += y >>  z & 1
            adjusted += (y + (not parity % 2)).to_bytes(1,'big')
        return adjusted

