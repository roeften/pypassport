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

# Source: www.RFIDIOt.org by Adam Laurie
# Only implement -5 part about biometric pictures

from operator import and_
from pypassport.hexfunctions import *

FAC= '46414300'

# ISO 19794_5 (Biometric identifiers)
ISO19794_5_GENDER= {'00':'Unpecified',
                    '01':'Male',
                    '02':'Female',
                    '03':'Unknown'
                   }

ISO19794_5_EYECOLOUR= {'00':'Unspecified',
                       '01':'Black',
                       '02':'Blue',
                       '03':'Brown',
                       '04':'Grey',
                       '05':'Green',
                       '06':'Multi',
                       '07':'Pink',
                       '08':'Other'
                      }

ISO19794_5_HAIRCOLOUR= {'00':'Unspecified',
                        '01':'Bald',
                        '02':'Black',
                        '03':'Blonde',
                        '04':'Brown',
                        '05':'Grey',
                        '06':'White',
                        '07':'Red',
                        '08':'Green',
                        '09':'Blue',
                        'ff':'Other'
                       }    

ISO19794_5_FEATURE= {0x01:'Specified',
                     0x02:'Glasses',
                     0x04:'Moustache',
                     0x08:'Beard',
                     0x10:'Teeth Visible',
                     0x20:'Blink',
                     0x40:'Mouth Open',
                     0x80:'Left Eyepatch',
                     0x100:'Right Eyepatch',
                     0x200:'Dark Glasses',
                     0x400:'Distorted'                     
                    }

ISO19794_5_EXPRESSION= {'0000':'Unspecified',
                        '0001':'Neutral',
                        '0002':'Smile Closed',
                        '0003':'Smile Open',
                        '0004':'Raised Eyebrow',
                        '0005':'Looking Away',
                        '0006':'Squinting',
                        '0007':'Frowning'
                       }

ISO19794_5_IMG_TYPE= {'00':'Unspecified (Front)',
                      '01':'Basic',
                      '02':'Full Front',
                      '03':'Token Front',
                      '04':'Other'
                      }

ISO19794_5_IMG_DTYPE= {'00':'JPEG',
                       '01':'JPEG 2000'
                      }

ISO19794_5_IMG_FTYPE= {'00':'JPG',
                       '01':'JP2'
                      }

ISO19794_5_IMG_CSPACE= {'00':'Unspecified',
                        '01':'RGB24',
                        '02':'YUV422',
                        '03':'GREY8BIT',
                        '04':'Other'
                       }

ISO19794_5_IMG_SOURCE= {'00':'Unspecified',
                        '01':'Static Unspecified',
                        '02':'Static Digital',
                        '03':'Static Scan',
                        '04':'Video Unknown',
                        '05':'Video Analogue',
                        '06':'Video Digital',
                        '07':'Unknown'
                       }

ISO19794_5_IMG_QUALITY= {'0000':'Unspecified'}

class ISO19794_5:
    """ Implement the ISO19794-5 concerning biometric Facial Pictures """
    
    @staticmethod
    def analyse(data):
        """ Analyze the content of the CBEFF header
        
            @param data: Image Block with header
            @type data: binary data
            
            @return: tuple composed of header size and decoded header
            @rtype: tuple(int, dict)        
        """
         
        offset = 0
        result = {}
        
        tag = data[offset:offset+8]
        offset += 8
        if tag != FAC:
            raise Exception("Missing FAC in CBEFF block:"+tag)
        
        tag = data[offset:offset+6]
        offset += 8
        result['VersionNumber'] = hexRepToBin(tag)
        
        tag = data[offset:offset+8]
        offset += 8
        result['LengthOfRecord'] = int(tag,16)
        
        tag = data[offset:offset+4]
        offset += 4
        result['NumberOfFacialImages'] = int(tag,16)
        
        tag = data[offset:offset+8]
        offset += 8
        result['FaceImageBlockLength'] = int(tag,16)
        
        
        tag = data[offset:offset+4]
        offset += 4
        result['NumberOfFeaturePoint'] = int(tag,16)
       
        tag = data[offset:offset+2]
        offset += 2
        result['Gender'] = ISO19794_5_GENDER[tag]
        
        tag = data[offset:offset+2]
        offset += 2
        try:
            result['EyeColour'] = ISO19794_5_EYECOLOUR[tag]
        except KeyError:
            result['EyeColour'] = int(tag,16)
        
        tag = data[offset:offset+2]
        offset += 2
        try:
            result['HairColour'] = ISO19794_5_HAIRCOLOUR[tag]
        except KeyError:
            result['HairColour'] = int(tag,16)        
        
        tag = data[offset:offset+6]
        offset += 6
        result['FeatureMask'] = tag
        
        mask = int(tag,16)
        features = {}
        for key, value in list(ISO19794_5_FEATURE.items()):
            if and_(mask, key):
                features[key] = value
        result['Features'] = features        
                
        tag = data[offset:offset+4]
        offset += 4
        try:
            result['Expression'] = ISO19794_5_EXPRESSION[tag]
        except KeyError:
            result['Expression'] = int(tag,16)
        
        tag = data[offset:offset+6]
        offset += 6
        result['PoseAngle'] = tag
        
        tag = data[offset:offset+6]
        offset += 6
        result['PoseAngleUncertainty'] = tag
        
        features = {}
        for i in range(result['NumberOfFeaturePoint']):
            feature = {}
            tag = data[offset:offset+2]
            offset += 2
            feature['FeatureType'] = tag # 1 == 2D; other RFU
            
            tag = data[offset:offset+2]
            offset += 2
            feature['FeaturePointCode'] = tag
            
            tag = data[offset:offset+4]
            offset += 4
            feature['HorizontalPosition'] = int(tag,16)
            
            tag = data[offset:offset+4]
            offset += 4
            feature['VerticalPosition'] = int(tag,16)
            
            tag = data[offset:offset+4]
            offset += 4
            feature['Reserved'] = tag

            features[i] = feature
            
        result['FeaturePoint'] = features
        
        tag = data[offset:offset+2]
        offset += 2
        try:
            result['FaceImageType'] = ISO19794_5_IMG_TYPE[tag]
        except KeyError:
            result['FaceImageType'] = int(tag,16)             
        
        tag = data[offset:offset+2]
        offset += 2
        try:
            result['ImageDataType'] = ISO19794_5_IMG_DTYPE[tag]
        except KeyError:
            result['ImageDataType'] = int(tag,16)             
        
        tag = data[offset:offset+4]
        offset += 4
        result['ImageWidth'] = int(tag,16)
        
        tag = data[offset:offset+4]
        offset += 4
        result['ImageHeight'] = int(tag,16)
        
        tag = data[offset:offset+2]
        offset += 2
        try:
            result['ImageColourSpace'] = ISO19794_5_IMG_CSPACE[tag]
        except KeyError:
            result['ImageColourSpace'] = int(tag,16)            
        
        tag = data[offset:offset+2]
        offset += 2
        try:
            result['ImageSourceType'] = ISO19794_5_IMG_SOURCE[tag]
        except KeyError:
            result['ImageSourceType'] = int(tag,16)              
        
        tag = data[offset:offset+4]
        offset += 4
        result['ImageDeviceType'] = int(tag,16)
        
        tag = data[offset:offset+4]
        offset += 4
        result['ImageQuality'] = ISO19794_5_IMG_QUALITY[tag]
        
        return ( int(offset/2), result)
    
    @staticmethod
    def createHeader(imageType, imageHeight, imageWidth, imageSize):
        """ create a simple CBEFF header based on image information

            @param imageType: Format of the image
            @type imageType: string from IMAGETYPE dictionnary
            @param imageHeight: Height of the image in pixels
            @type imageHeight: int
            @param imageWidth: Width of the image in pixels
            @type imageWidth: int
            @param imageSize: size of the image in bytes
            @type imageSize: int        
        """
        
        IMAGETYPE = {'JPEG': "00",
                     'JPG': "00",
                     'JPEG2000': "01",
                     'JP2': "01"
                     }
        
        header = "46414300"
        version = "30313000" # '101' 0x0
        recordLength = intToHexRep(imageSize + 46, 8)
        numberOfImage = "0001"
        
        ImageBlockLength = intToHexRep(imageSize + 32, 8) # no feature point
        numberOfFeaturePoint= "0000"
        gender = "00"
        eyeColour = "00"
        hairColour = "00"
        featureMask = "000000"
        expression = "0000"
        poseAngle = "000000"
        poseAngleUncertainty = "000000"
        imageFaceType = "00"
        imageDataType = IMAGETYPE[imageType]
        width = intToHexRep(imageWidth, 4)
        height = intToHexRep(imageHeight, 4)
        colourSpace = "00"
        sourceType = "00"
        deviceType = "0000"
        quality = "0000"
        
        return hexRepToBin(header+version+recordLength+numberOfImage+ImageBlockLength+numberOfFeaturePoint+gender\
                           +eyeColour+hairColour+featureMask+expression+poseAngle+poseAngleUncertainty\
                           +imageFaceType+imageDataType+width+height+colourSpace+sourceType+deviceType+quality)