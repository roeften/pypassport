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
from string import replace
import subprocess
from pypassport.logger import Logger

class GeoJasperException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)
        
class GeoJasper(Logger):
    
    def __init__(self, geojasperLocation="geojasper"):
        Logger.__init__(self)
        self._geojasperLocation = geojasperLocation

    def _getGeojasperLocation(self):
        return self._geojasperLocation

    def _setGeojasperLocation(self, value):
        self._geojasperLocation = value
        
    def _execute(self, toExecute, empty=False):
    
        cmd = self._geojasperLocation + " " + toExecute
        self.log(cmd)

        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = res.stdout.read()
        err = res.stderr.read()
        
        if ((not out) and err and not empty):
            raise GeoJasperException(err)
        
        return out
    
    def _isGeoJasperSSL(self):
        cmd = "--version"
        try:
            return self._execute(cmd)
        except GeoJasperException as msg:
            return False
        
    def convert(self, inFile, outFile="tmp.jpg"):
        self._execute("-f "+inFile+" -F "+outFile)
        
    def toDisk(self, data, file="tmp.jp2"):
        jp2 = open(file, "wb")
        jp2.write(data)
        jp2.close()

    location = property(_getGeojasperLocation, _setGeojasperLocation, None, None)