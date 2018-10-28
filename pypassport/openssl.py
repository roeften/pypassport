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

import os, shutil
import subprocess
from pypassport import hexfunctions
from pypassport.logger import Logger

class OpenSSLException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class OpenSSL(Logger):
    
    def __init__(self, config="", opensslLocation="openssl"):
        Logger.__init__(self, "OPENSSL")
        self._opensslLocation = opensslLocation
        self._config = config

    def _getOpensslLocation(self):
        return self._opensslLocation


    def _setOpensslLocation(self, value):
        self._opensslLocation = value

    def getPkcs7SignatureContent(self, p7b):
        """
        Return the data contained in the pkcs#7 signature.
        @param p7b: A pkcs#7 signature in der format
        @return: The data contained in the signature
        """
        try:
            self._toDisk("p7b", p7b)
            return self._execute("smime -verify -in p7b -inform DER -noverify")
        finally:
            self._remFromDisk("p7b")
            
    def verifyX509Certificate(self, certif, trustedCertif):
        """
        Verify the x509 certificate.
        @param certif: The certificate to verify
        @param trustedCertif: The directory containing the root certificates
        @return: True if correct
        """
        try:
            self._toDisk("certif.cer", certif)
            data = self._execute("verify -CApath "+trustedCertif+" certif.cer")       
            data = str.replace(data, "certif.cer: ", "")
        finally:
            self._remFromDisk("certif.cer")

        if data[:2] == "OK":
            return True
        raise OpenSSLException(data.strip())
    
    def retrievePkcs7Certificate(self, derFile):
        """ 
        Retrieve the certificate from the binary string, and returns it
        into a human readable format.
        @param derFile: The certificate in der format
        @return: The certificate in a human readable format
        """
        try:
            self._toDisk("data.der", derFile)
            return self._execute("pkcs7 -in data.der -inform DER -print_certs -text")
        finally:
            self._remFromDisk("data.der")
            
    def retrieveRsaPubKey(self, derFile):
        """ 
        Transform the rsa public key in der format to pem format" 
        @param derFile: A rsa public key in der format
        @return: The rsa public key in pem formar
        """
        
        try:
            self._toDisk("pubK", derFile)
            return self._execute("rsa -in pubK -inform DER -pubin -text")
        finally:
            self._remFromDisk("pubK")
            
    def retrieveSignedData(self, pubK, signature):
        """ 
        Retrieve the signed data from the signature
        @param pubK: A RSA public key in der format
        @param signature: The signature to verify with the pubKey
        @return: The data contained in the signature
        """
        
        #Verify if openSSL is installed
        self._execute("version")
        data = None
        try:
            self._toDisk("pubK", pubK)
            self._toDisk("signature", signature)
            self._execute("rsautl -inkey pubK -in signature -verify -pubin -raw -out res -keyform DER", True)
            sig = open("res", "rb")
            data = sig.read()
            sig.close()
        finally:
            self._remFromDisk("pubK")
            self._remFromDisk("challenge")
            self._remFromDisk("res")
            self._remFromDisk("signature")
        
        return data
    
    def signData(self, sodContent, ds, dsKey):
        bkup = self._opensslLocation
        
        try:
            p12 = self.toPKCS12(ds, dsKey, "titus")
            dsDer = self.x509ToDER(ds)
            
            self._toDisk("sodContent", sodContent)
            self._toDisk("p12", p12)
            self._toDisk("ds.cer", dsDer)
            
            self._opensslLocation = "java -jar "
            cmd = "createSod.jar --certificate ds.cer --content sodContent --keypass titus --privatekey p12 --out signed"
            res = self._execute(cmd, True)
            f = open("signed", "rb")
            res = f.read()
            f.close()
            return res
        finally:
            self._opensslLocation = bkup
            self._remFromDisk("sodContent")
            self._remFromDisk("p12")
            self._remFromDisk("ds.cer")
            self._remFromDisk("signed")
            
            
    
    def genRSAprKey(self, size):
        """ 
        Return an RSA private key of the specified size in PEM format.
        """
        return self._execute("genrsa " + str(size))
    

    
    def genRootX509(self, cscaKey, validity="",  distinguishedName=None):
        """
        Generate a x509 self-signed certificate in PEM format
        """
        try:
            if distinguishedName:
                subj = distinguishedName.getSubject()
            else:
                subj = DistinguishedName(C="BE", O="Gouv", CN="CSCA-BELGIUM").getSubject()
            
            self._toDisk("csca.key", cscaKey)
            cmd = "req -new -x509 -key csca.key -batch -text"
            if self._config:
                cmd += " -config " + self._config
            if subj:
                cmd += " -subj " + subj
            if validity:
                cmd += " -days " + str(validity)
            return self._execute(cmd)
        finally:
            self._remFromDisk("csca.key")
    
    def genX509Req(self, dsKey, distinguishedName=None):
        """
        Generate a x509 request in PEM format
        """
        try:
            if distinguishedName:
                subj = distinguishedName.getSubject()
            else:
                subj = DistinguishedName(C="BE", O="Gouv", CN="Document Signer BELGIUM").getSubject()
            
            self._toDisk("ds.key", dsKey)
            cmd = "req -new -key ds.key -batch"
            if self._config:
                cmd += " -config " + self._config
            if subj:
                cmd += " -subj " + str(subj)
            return self._execute(cmd)
        finally:
            self._remFromDisk("ds.key")
            
    def signX509Req(self, csr, csca, cscaKey, validity=""):
        """
        Sign the request with the root certificate. Return a x509 certificate in PEM format
        
        @param csr: The certificate request
        @param csca: The root certificate
        @param cscaKey: The CA private key
        @param validity: The validity of the signed certificate
        """
        try:
            self._toDisk("ds.csr", csr)
            self._toDisk("csca.pem", csca)
            self._toDisk("csca.key", cscaKey)
            cmd = "ca -in ds.csr -keyfile csca.key -cert csca.pem  -batch"
            if self._config:
                cmd += " -config " + self._config
            if validity:
                cmd += " -days " + str(validity)
            return self._execute(cmd)
            
        finally:
            self._remFromDisk("ds.csr")
            self._remFromDisk("csca.pem")
            self._remFromDisk("csca.key")
            
    def genCRL(self, csca, cscaKey):
        """ 
        @param csca: The root certificate
        @param cscaKey: The CA private key
        """
        
        try:
            self._toDisk("csca.pem", csca)
            self._toDisk("csca.key", cscaKey)
            cmd = "ca -gencrl -cert csca.pem -keyfile csca.key"
            if self._config:
                cmd += " -config " + self._config
            return self._execute(cmd)
        finally:
            self._remFromDisk("csca.pem")
            self._remFromDisk("csca.key")
            
    def revokeX509(self, cert, csca, cscaKey):
        """ 
        @param csca: The root certificate
        @param cscaKey: The CA private key
        """
        try:
            self._toDisk("toRevoke", cert)
            self._toDisk("csca.pem", csca)
            self._toDisk("csca.key", cscaKey)
            cmd = "ca -revoke toRevoke -cert csca.pem -keyfile csca.key"
            if self._config:
                cmd += " -config " + self._config
            return self._execute(cmd, True)
        finally:
            self._remFromDisk("toRevoke")
            self._remFromDisk("csca.pem")
            self._remFromDisk("csca.key")

    
    def toPKCS12(self, certif, prK, pwd):
        """  
        Return a RSA key pair under the PKCS#12 format.
        PKCS#12: used to store private keys with accompanying public key certificates, protected with a password-based symmetric key
        """
        try:
            self._toDisk("certif", certif)
            self._toDisk("prK", prK)
            return self._execute("pkcs12 -export -in certif -inkey prK -passout pass:" + pwd)
        finally: 
            self._remFromDisk("certif")
            self._remFromDisk("prK")
            
    def x509ToDER(self, certif):
        try:
            self._toDisk("pem", certif)
            return self._execute("x509 -in pem -outform DER")
        finally:
            self._remFromDisk("pem")
            
    def prRSAToDERPb(self, prKey):
        """ 
        Retrieve the corresponding DER encoded public key fron the given a RSA private key
        """
        try:
            self._toDisk("dg15", prKey)
            return self._execute("rsa -pubout -in dg15 -outform der")
        finally:
            self._remFromDisk("dg15")
            
    def RSAKeyToText(self, key):
        """ 
        COnvert a key to its text format
        """
        try:
            self._toDisk("key", key)
            return self._execute("rsa -text -in key")
        finally:
            self._remFromDisk("key")
            
    def crlToDER(self, crl):
        try:
            self._toDisk("crl", crl)
            return self._execute("crl -inform PEM -in crl -outform DER")
        finally:
            self._remFromDisk("crl")
                    
    def _toDisk(self, name, data=None):
        f = open(name, "wb")
        if data: f.write(data)
        f.close()
        
    def _remFromDisk(self, name):
        try:
            os.remove(name)
        except:
            pass
        
    def _execute(self, toExecute, empty=False):
        
        cmd = self._opensslLocation + " " + toExecute
        self.log(cmd)

        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = res.stdout.read()
        err = res.stderr.read()
        
        if ((not out) and err and not empty):
            raise OpenSSLException(err)
        
        if(err):
            self.log(err)
        
        return out
    
    def _isOpenSSL(self):
        cmd = "version"
        try:
            return self._execute(cmd)
        except OpenSSLException as msg:
            return False
                  
    def printCrl(self, crl):
        try:
            self._toDisk("crl", crl)
            cmd = 'crl -in crl -text -noout -inform DER'
            return self._execute(cmd)
        finally:
            self._remFromDisk("crl")

    location = property(_getOpensslLocation, _setOpensslLocation, None, None)
    
        