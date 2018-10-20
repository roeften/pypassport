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

from pypassport import epassport, reader
import os, string

MRZ_bob       = "EH123456<0BEL8510035M1508075<<<<<<<<<<<<<<02"
MRZ_oli       = "EH276509<0BEL8406158M1302217<<<<<<<<<<<<<<04"
MRZ_helen     = "EF486766<8BEL8803023F1103056<<<<<<<<<<<<<<00"
MRZ_fred      = "EG491433<0BEL8305099M1208157<<<<<<<<<<<<<<04"
MRZ_camille   = "08CH022724FRA8706021F1807066<<<<<<<<<<<<<<06"
MRZ_nico      = "EH288866<9BEL8605113M1303269<<<<<<<<<<<<<<00"
MRZ_caro      = "EH266828<7BEL8405243F1302206<<<<<<<<<<<<<<02"
MRZ_n =         "7065198411GBR9703072M1206256<<<<<<<<<<<<<<02"

#Remplire la 2e ligne ici
#MRZ_ = "4479426958USA4307121M1806173228204573<883790"
##Dir ou enregistrer les dumps
#DIR_DUMP = "c:\\tmp"

def trace(name, msg):
    if name == "EPassport":
        print(name + "> " + msg)

sep = os.path.sep
Sim = False
r=None
if not Sim:
    r = reader.ReaderManager().waitForCard()
    
else:
    r = reader.ReaderManager().create("DumpReader")
    r.connect("C:\\tmp")

ep = epassport.EPassport(r, MRZ_oli)
ep.register(trace)
ep.setCSCADirectory(os.getcwd() + sep + "data" + sep + "cert", False)

import time

start = time.time()
ep.readPassport()
print(time.time() - start)


if False:
    try:
        ep.doVerifySODCertificate()
    except Exception as msg:
       print(msg)
    try:
        p = ep.readDataGroups()
        print(ep.doVerifyDGIntegrity(p))
    except Exception as msg:
        print(msg)

if False:
    ep.doActiveAuthentication()
