## Copyright 2009 Jean-Francois Houzard, Olivier Roger
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

class OIDException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

#Use a value that can be evaluated by a Crypto lib.
#Here SHA and SHA256 are two classes from Crypto.Hash import *
#So the passiveAuth class can just do an eval( OID['oid'] ) to get the algo class
OID = {
    "1.3.14.3.2.26" : "sha1",
    "2.16.840.1.101.3.4.2.4" : "sha224",
    "2.16.840.1.101.3.4.2.1" : "sha256",
    "2.16.840.1.101.3.4.2.2" : "sha384",
    "2.16.840.1.101.3.4.2.3" : "sha512",
    "1.2.840.113549.1.1.1" : "RSA (PKCS #1 v1.5)"
}

OIDrevert = {
    "sha1" : "1.3.14.3.2.26",
    "sha224" :"2.16.840.1.101.3.4.2.4",
    "sha256" : "2.16.840.1.101.3.4.2.1",
    "sha384" : "2.16.840.1.101.3.4.2.2",
    "sha512" : "2.16.840.1.101.3.4.2.3",
    "RSA (PKCS #1 v1.5)" : "1.2.840.113549.1.1.1"
}
