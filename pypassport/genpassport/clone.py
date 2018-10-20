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
from pypassport.doc9303 import converter
from pypassport.genpassport import epassportcreation, jcop

Sim = True
r=None

APPLET = False
READER_NUM = 2
APPLET_PATH = "D:\\download\\epassport_emulator_v1.02\\epassport.cap" 
MRZ = "EG491433<0BEL8305099M1208157<<<<<<<<<<<<<<04"
DUMP_DIR = "../testData"

if not Sim:
    print("Put the original ePassport on the reader")
    r = reader.ReaderManager().waitForCard()
else:
    r = reader.ReaderManager().create("DumpReader")
    r.format = converter.types.GRT
    r.ext = ".bin"
    r.connect(DUMP_DIR)
    

ep = epassport.EPassport(r, MRZ)
ep.readPassport()


if APPLET:
    input("Applet upload: Put the JCOP on the reader, and press a key")
    jc = jcop.GPlatform(READER_NUM)
    jc.install(APPLET_PATH)
    

input("Dumps upload: Put the JCOP on the reader, and press a key") 
r = reader.ReaderManager().waitForCard()
epc = epassportcreation.EPassportCreator(None, None, r)
epc.setEPassport(ep)
print(epc.toJCOP())

