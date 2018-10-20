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

class MRZException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class MRZ(object):
    
    """   
    This class implement the mrz check digit test.
    The class is used when the mrz is encoded by the user, to verify the mrz validity.
    The method I{checkMRZ} must be called before any further use of this class because
    it will populate the fields of the class.
    When the check is done, this class is used by the BAC class to get the fields necessary for the key derivation.
    
    Two type of MRZ are handled: TD1 and TD2.
    """
    
    def __init__(self, mrz):
        self._mrz = mrz
        self._weighting = [7,3,1]
        self._weight = {'0':0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9, '<':0,
          'A':10, 'B':11, 'C':12, 'D':13, 'E':14, 'F':15, 'G':16, 'H':17, 'I':18, 'J':19, 'K':20, 'L':21, 'M':22, 
          'N':23, 'O':24, 'P':25, 'Q':26, 'R':27, 'S':28, 'T':29, 'U':30, 'V':31, 'W':32, 'X':33, 'Y':34, 'Z':35};
        
        self._docNumber = None
        self._docNumberCD = None
        self._dateOfBirth = None
        self._dateOfBirthCD = None
        self._dateOfExpiry = None
        self._dateOfExpiryCD = None
        self._checked = None

    def getDocNumber(self):
        return (self._docNumber, self._docNumberCD)

    def getDateOfBirth(self):
        return (self._dateOfBirth, self._dateOfBirthCD)

    def getDateOfExpiry(self):
        return (self._dateOfExpiry, self._dateOfExpiryCD)
    
    def getChecked(self):
        return self._checked

    def checkMRZ(self):
        """ 
        The method verify the check digits of the encoded MRZ.
        It handle two kind of MRZ: TD1 and TD2.
        The method retrieves the fields used by the bac protocol, so this method
        must be called after the mrz object initialization. 
        
        @return: True or False
        @rtype: A boolean       
        """
        mrz = self._mrz
        if len(mrz) == 60:
            self._checked = self._checkDigitsTD1(mrz[:30], mrz[30:])
        elif len(mrz) == 44:
            self._checked = self._checkDigitsTD2(mrz)
        else: raise MRZException("The mrz length is invalid")
        
        return self._checked
    
    def _checkDigitsTD1(self, mrz1, mrz2):
        
        if mrz1[14] == "<":
            #Document number is bigger than 9 caracters
            tmp = mrz1[15:30].strip("<")
            self._docNumber = mrz[5:14] + tmp[:-1]
            self._docNumberCD = tmp[-1]
        else:
            self._docNumber = mrz[5:14]
            self._docNumberCD = mrz[14]
            
        self._dateOfBirth = mrz2[0:6]
        self._dateOfBirthCD = mrz2[6]
        self._dateOfExpiry = mrz2[8:14]
        self._dateOfExpiryCD = mrz2[14]
        
        fields = [
                     (self._docNumber, self._docNumberCD), 
                     (self._dateOfBirth, self._dateOfBirthCD),
                     (self._dateOfExpiry, self._dateOfExpiryCD),
                     (mrz1[5:30] + mrz2[0:7] + mrz2[8:15] + mrz2[18:29] , mrz2[29])
                     ]

        
            
        return self._checkDigits(fields)
    
    def _checkDigitsTD2(self, mrz):
        
        if mrz[9] == "<":
            #Document number is bigger than 9 caracters
            tmp = mrz[24:35].strip("<")
            self._docNumber = mrz[0:9] + tmp[:-1]
            cd = tmp[-1]
        else:
            self._docNumber = mrz[0:9]
            self._docNumberCD = mrz[9]
            
        self._dateOfBirth = mrz[13:19]
        self._dateOfBirthCD = mrz[19]
        self._dateOfExpiry = mrz[21:27]
        self._dateOfExpiryCD = mrz[27]
        
        fields = [
                  (self._docNumber, self._docNumberCD),
                  (self._dateOfBirth, self._dateOfBirthCD),
                  (self._dateOfExpiry, self._dateOfExpiryCD),
                  (mrz[0:10] + mrz[13:20] + mrz[21:-1], mrz[-1])
                   ]

            
        return self._checkDigits(fields)
    
    def _checkDigits(self, data):

        try:
            for (field, cd) in data:
                res = self._calculCheckDigit(field)
                if str(res) != str(cd): 
                    return False
            return True
        except KeyError:
            return False
        
    def _calculCheckDigit(self, value):
        """ Create check digit for a value of the MRZ 
        
            @param value: initial value
            @type value: String
            @return: Check digit
            @rtype: String
            
            @note: Code fragment from the pyPassport.mrz.MRZ class
        """
        cpt=0
        res=0
        for x in value:
            tmp = self._weight[str(x)] * self._weighting[cpt%3]
            res += tmp
            cpt += 1
        return str(res%10)
        
    def buildMRZ(self, type, issuer, name, firstname, nat, sex, num, birth, exp):
        """ Build MRZ using the informations given by dates and passport number 
        
            @note: sex and nat field are not necessary to BAC and are then 
                   replaced by '<' characters
                   
            @attention: this method build a 44 characters MRZ based on TD2 specs
            @attention: if passport number is larger than its reserved space
                        the rest il put in the optional field with the check digit
                        initial check digit il replaced by a '<' character
        """
        type = self._transformField(type, 2)
        issuer = self._transformField(issuer, 3) 
        name_firstName = self._transformField(name + "<<" + firstname, 39)
        line1 = self._transformField(type + issuer + name_firstName, 44)
        
        #num = self._transformField(num, 9)
        nat = self._transformField(nat, 3)
        birth = self._transformField(birth, 6)
        sex = self._transformField(sex, 1)
        exp = self._transformField(exp, 6)
        
        line2 = ''
        
        if len(num) <= 9:
            optional = ""
            num = num + "<" * (9 -len(num))
            numCD = self._calculCheckDigit(num)
        else:
            optional = num[9:]
            num = num[:9]
            numCD = '<'
            optional = optional + self._calculCheckDigit(optional)
            
        birthCD = self._calculCheckDigit(birth)
        expCD = self._calculCheckDigit(exp)
        line2 = num + numCD + nat + birth + birthCD + sex + exp + expCD
        optional = optional + "<" * (42-len(line2)-len(optional))
        optionalCD = self._calculCheckDigit(optional)
        data = line2 + optional + optionalCD
        compositeCD = self._calculCheckDigit(num+numCD+birth+birthCD+exp+expCD+optional+optionalCD)
        line2 = data + compositeCD
        
        return line1 + line2 
    
    def _transformField(self, field, size):
        if len(field) > size:
            raise MRZException("The filed length is incorrect (" + field + "): " + str(len(field)) + " instead of " + str(size))
        
        field = field.replace(' ', '<').upper()
        field = field.replace('.', '<').upper()
        field = field.replace('-', '<').upper()
        field = field.replace(',', '').upper()
        return field + "<" * (size - len(field))
    
    def getMrz(self):
        return self._mrz
    
    def __str__(self):
        return self._mrz

    docNumber = property(getDocNumber)
    dateOfBirth = property(getDateOfBirth)
    dateOfExpiry = property(getDateOfExpiry)
    checked = property(getChecked)
    
