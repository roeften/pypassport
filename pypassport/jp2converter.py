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
import sys


class jp2ConverterException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


def ConvertJp2(input_):
    """
    If the input is a jp2 picture, the image is transformed into bmp,
    else the image is returned without any modifications.

    @param input_: A binary string representing the picture to convert
    @type input_: A string
    @return: A binary string representing the picture in bmp, or the original input if the input is not a jp2 stream.
    """

    with open("tmp.jp2", "wb") as jp2:
        jp2.write(input_)

    local = ""
    if (sys.platform != "win32") and os.path.isfile('geojasper'):
        local = "./"
    a = os.popen(local+"geojasper -f tmp.jp2 -F tmp.jpg")
    a.close()

    try:
        with open("tmp.jpg", "rb") as f:
            input_ = f.read()
    except IOError:
        pass
    finally:
        try:
            os.remove("tmp.jp2")
            os.remove("tmp.jpg")
        except BaseException:
            pass

    return input_
