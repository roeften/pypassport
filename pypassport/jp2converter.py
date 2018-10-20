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

import os, sys

class jp2ConverterException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

def ConvertJp2(input):
    """ 
    If the input is a jp2 picture, the image is transformed into bmp,
    else the image is returned without any modifications.
    
    @param input: A binary string representing the picture to convert
    @type input: A string
    @return: A binary string representing the picture in bmp, or the original input if the input is not a jp2 stream. 
    """
    
    jp2 = open("tmp.jp2", "wb")
    jp2.write(input)
    jp2.close()
    
    local = ""
    if (sys.platform != "win32") and os.path.isfile('geojasper'):
        local = "./"
    a=os.popen(local+"geojasper -f tmp.jp2 -F tmp.jpg")
    a.close()
    
    try:
        f = open("tmp.jpg", "rb")
        input = f.read()
        f.close()
    except IOError as msg:
        pass
    finally:
        try:
            os.remove("tmp.jp2")
            os.remove("tmp.jpg")
        except:
            pass
        
    return input