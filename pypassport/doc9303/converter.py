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

class types(object):
    DG = "DG"
    EF = "EF"
    SEF = "SEF"
    FID = "FID"
    TAG = "TAG"
    CLASS = "CLASS"
    OTHER = "OTHER"
    ORDER = "ORDER"
    GRT = "GRT"

_Table = {
         types.DG : ["Common", "DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7", "DG8", "DG9", "DG10", "DG11", "DG12", "DG13", "DG14", "DG15", "DG16", "SecurityData","CardAccess"],
         types.EF : ["EF.COM", "EF.DG1", "EF.DG2", "EF.DG3", "EF.DG4", "EF.DG5", "EF.DG6", "EF.DG7", "EF.DG8", "EF.DG9", "EF.DG10", "EF.DG11", "EF.DG12", "EF.DG13", "EF.DG14", "EF.DG15", "EF.DG16", "EF.SOD","EF.CARDACCESS"],
         types.SEF : ["1E", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10", "1D","1C"],
         types.FID : ["011E", "0101", "0102", "0103", "0104", "0105", "0106", "0107", "0108", "0109", "010A", "010B", "010C", "010D", "010E", "010F", "0110", "011D","011C"],
         types.TAG : ["60", "61", "75", "63", "76", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "77", "42"],
         types.CLASS : ["Com", "DataGroup1", "DataGroup2", "DataGroup3", "DataGroup4", "DataGroup5", \
                "DataGroup6", "DataGroup7",  "DataGroup8", "DataGroup9", "DataGroup10", \
                "DataGroup11", "DataGroup12", "DataGroup13", "DataGroup14", "DataGroup15", \
                "DataGroup16", "SOD", "CardAccess"],
         types.OTHER : ["EF", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "SOD", "CARDACCESS"],
         types.ORDER : ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18"],
         types.GRT : ["EF_COM", "Datagroup1", "Datagroup2", "Datagroup3", "Datagroup4", "Datagroup5", "Datagroup6", "Datagroup7", "Datagroup8", "Datagroup9", "Datagroup10", "Datagroup11", "Datagroup12", "Datagroup13", "Datagroup14", "Datagroup15", "Datagroup16", "EF_SOD", "EF_CARDACCESS"]
         }
    
def toDG(data):
    """ 
    Transform the data value to its DG representation
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.DG, data)

def toEF(data):
    """ 
    Transform the data value to its EF representation
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.EF, data)

def toSEF(data):
    """ 
    Transform the data value to its SEF representation
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.SEF, data)

def toFID(data):
    """ 
    Transform the data value to its FID representation
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.FID, data)

def toTAG(data):
    """ 
    Transform the data value to its TAG representation
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.TAG, data)

def toClass(data):
    """ 
    Return the class linked to the parameter value
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.CLASS, data)

def toOther(data):
    """ 
    Transform the data value to its OTHER representation
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.OTHER, data)

def toOrder(data):
    """ 
    Transform the data value to its ORDER representation (0 to 17)
    If the data value does not come from the Table A1 from the doc9303, 
    an exception is raised
    """
    return to(types.ORDER, data)

def toGRT(data):
    """ 
    Transform the data value to its GoldenReaderTool representation
    """
    return to(types.GRT, data)

def to(table, data):
    """ 
    Return the element value from the specified list at the found possition
    """
    return _Table[table][_getPosition(data)]
        
def _getPosition(data):
    """ 
    Look for the corresponding data value in every list of the _Table dictionnary.
    If The data value is found, it's position is returned.
    """
    
    for l in _Table:
        try:
            return _Table[l].index(str(data))
        except ValueError:
            pass
    raise KeyError("Invalid Data Group: "+ str(data))
