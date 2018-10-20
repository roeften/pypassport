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
from pypassport import openssl, reader
from pypassport import pki
from pypassport.doc9303 import datagroup
from pypassport.genpassport import epassportcreation, jcop
import time

#Activate the trace log
TRACE = True
#Store dump on disk
DUMP = False
#Install the applet in the JCOP
INSTALL_APPLET = True
#Send dump to JCOP
JCOP = True #An ePassport emulator applet must be installer on the JCOP
#create a new set of certitificates
CREATE_CERT = False
#Set the location where certificates and dump are stored/loaded
WORKING_DIR = "C:/tmp"
#Set the applet path for the JCOP applet set up
APPLET_PATH = "D:\\download\\epassport_emulator_v1.02\\epassport.cap"
#Set the reader number for the JCOP applet set up
READER_NUM = 2

def trace(name, str):
    if TRACE:
        print(name + "> " + str)

#Set the Country Signing CA information
CSCA = pki.DistinguishedName(
    C="BE", 
    O="UCL", 
    CN="CSCA-HOUZARD"
)
CSCA_KEY_SIZE = 1024
CSCA_VALIDITY_PERIOD = 720

#Set the Document Signer Certificate information
DS = pki.DistinguishedName(
    C="BE", 
    O="UCL", 
    CN="Document_Signer_ROGER"
)
DS_KEY_SIZE = 1024
DS_VALIDITY_PERIOD = 365

#Set the passport information
ISSUER = "BEL"                        #3 chars
NAME = "Smith"
SURNAME = "John"#39 chars for both n and fn
NATIONALITY = "BEL"                   #3 chars
SEX = "M"                             #1 char
PASSPORT_NUM = "EH123456"             #9 chars
BIRTH_DATE = "031085"                 #6 chars
EXPIRY_DATE = "070815"                #6 chars

ISSUE_DATA = "11072009"                 #6 chars
IMAGE_PATH = "C:/jf.jpg"
SIGNATURE_PATH = "C:/jfSignature.jpg"
BIRTH_PLACE = "Huy"
AUTHORITY = "MODAVE"  

o = openssl.OpenSSL()
o.register(trace)        
       
if not CREATE_CERT:
    f = open(WORKING_DIR + "\\csca")
    csca = f.read()
    f.close()
    f = open(WORKING_DIR + "\\cscaKey")
    cscaKey = f.read()
    f.close()
    f = open(WORKING_DIR + "\\ds")
    ds = f.read()
    f.close()
    f = open(WORKING_DIR + "\\dsKey")
    dsKey = f.read()
    f.close()
    
    ca = pki.CA(csca=csca, cscaKey=cscaKey)
    ca.register(trace)
else:
    ca = pki.CA()
    ca.register(trace)
    
    dgd = datagroup.DataGroupDump(WORKING_DIR)
    #Generate the CSCA Certificate and its private key in PEM
    (csca, cscaKey) = ca.createCSCA(CSCA_KEY_SIZE, CSCA_VALIDITY_PERIOD, CSCA)
    dgd.dumpData(csca, "csca")
    dgd.dumpData(cscaKey, "cscaKey")
    dgd.dumpData(o.x509ToDER(csca), "csca.cer")
    ##Generate the DS Certificate and its private key in PEM
    (ds, dsKey) = ca.createDS(DS_KEY_SIZE, DS_VALIDITY_PERIOD, DS)
    dgd.dumpData(ds, "ds")
    dgd.dumpData(dsKey, "dsKey")
    #Generate the CRL in DER
    crl = ca.getCrl()
    dgd.dumpData(crl, "csca.crl")
    
    
if INSTALL_APPLET:
    print('Installing applet') 
    jc = jcop.GPlatform(READER_NUM)
    jc.install(APPLET_PATH)
        
r = None
if JCOP:
    print('Drop the passport on the reader...')
    r = reader.ReaderManager().waitForCard()
    
#Generate the fake passport, and saves it   
epc = epassportcreation.EPassportCreator(ds, dsKey, r)
epc.register(trace)
epc.create(ISSUER, NAME, SURNAME, NATIONALITY, SEX, PASSPORT_NUM, BIRTH_DATE, EXPIRY_DATE, IMAGE_PATH, SIGNATURE_PATH, BIRTH_PLACE, AUTHORITY, ISSUE_DATA)


if DUMP:
    epc.toDisk("GRT", ".bin", WORKING_DIR)
    
if JCOP:
    print('Writting...')
    print("MRZ: " + epc.toJCOP())
