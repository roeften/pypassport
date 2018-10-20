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

from pypassport.hexfunctions import *
        
class CommandAPDU(object):
    def __init__(self, cla, ins, p1, p2, lc="", data="", le=""):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        
        self.lc = lc
        self.data = data
        self.le = le

    def getCla(self):
        return self.__cla


    def setCla(self, value):
        self.__cla = value


    def delCla(self):
        del self.__cla


    def getIns(self):
        return self.__ins


    def setIns(self, value):
        self.__ins = value


    def delIns(self):
        del self.__ins


    def getP1(self):
        return self.__p1


    def setP1(self, value):
        self.__p1 = value


    def delP1(self):
        del self.__p1


    def getP2(self):
        return self.__p2


    def setP2(self, value):
        self.__p2 = value


    def delP2(self):
        del self.__p2


    def getLc(self):
        return self.__lc


    def setLc(self, value):
        self.__lc = value


    def delLc(self):
        del self.__lc


    def getData(self):
        return self.__data


    def setData(self, value):
        self.__data = value


    def delData(self):
        del self.__data


    def getLe(self):
        return self.__le


    def setLe(self, value):
        self.__le = value


    def delLe(self):
        del self.__le

    def getBinAPDU(self):
        return hexRepToBin(self.getHexRepAPDU())
        
    def getHexRepAPDU(self):
        return self.cla + self.ins + self.p1 + self.p2 + self.lc + self.data + self.le
    
    def getHexListAPDU(self):
        return hexRepToList(self.getHexRepAPDU())
    
    def __str__(self):
        return "> " + self.cla + " " + self.ins + " " + self.p1 + " " + self.p2 + " " + self.lc + " [" + self.data + "] " + self.le
    
    cla = property(getCla, setCla, delCla, "Cla's Docstring")

    ins = property(getIns, setIns, delIns, "Ins's Docstring")

    p1 = property(getP1, setP1, delP1, "P1's Docstring")

    p2 = property(getP2, setP2, delP2, "P2's Docstring")

    lc = property(getLc, setLc, delLc, "Lc's Docstring")

    data = property(getData, setData, delData, "Data's Docstring")

    le = property(getLe, setLe, delLe, "Le's Docstring")
    
class ResponseAPDU(object):
    def __init__(self, res, sw1, sw2):
        self.__res = res
        self.__sw1 = sw1
        self.__sw2 = sw2

    def getRes(self):
        return self.__res

    def setRes(self, value):
        self.__res = value

    def getSW1(self):
        return self.__sw1

    def setSW1(self, value):
        self.__sw1 = value

    def getSW2(self):
        return self.__sw2

    def setSW2(self, value):
        self.__sw2 = value

    def getHexListAPDU(self):
        return self.res + [self.sw1] + [self.sw2]
    
    def getBinAPDU(self):
        return self.res + hexListToBin([self.sw1] + [self.sw2])
    
    def getHexRepAPDU(self):
        return binToHexRep(self.res) + hexToHexRep(self.sw1) + hexToHexRep(self.sw2)
    
    def __str__(self):
        return "< [" + binToHexRep(self.res) + "] " + hexToHexRep(self.sw1) + " " + hexToHexRep(self.sw2)

    res = property(getRes, setRes)

    sw1 = property(getSW1, setSW1)

    sw2 = property(getSW2, setSW2)


