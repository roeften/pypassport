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

# DOC9303-2 pg III-38

tagToName = {
#tagLDSToName = {
             "02" : "Integer",
             "5C" : "Tag list",
             
             "5F01" : "LDS Version Number",
             "5F08" : "Date of birth (truncated)",
             
             "5F09" : "Compressed image (ANSI/NIST-ITL 1-2000)",
             "5F0A" : "Security features - Encoded Data",
             "5F0B" : "Security features - Structure",
             "5F0C" : "Security features",
             "5F0E" : "Full name, in national characters",
             "5F0F" : "Other names",
             
             "5F10" : "Personal Number",
             "5F11" : "Place of birth",
             "5F12" : "Telephone",
             "5F13" : "Profession",
             "5F14" : "Title",
             "5F15" : "Personal Summary",
             "5F16" : "Proof of citizenship (10918 image)",
             "5F17" : "Other valid TD Numbers",
             "5F18" : "Custody information",
             "5F19" : "Issuing Authority",
             "5F1A" : "Other people on document",
             "5F1B" : "Endorsement/Observations",
             "5F1C" : "Tax/Exit requirements",
             "5F1D" : "Image of document front",
             "5F1E" : "Image of document rear",
             "5F1F" : "MRZ data elements",
             
             "5F26" : "Date of Issue",
             "5F2B" : "Date of birth (8 digit)",
             "5F2E" : "Biometric data block",
             
             "5F36" : "Unicode Version Level",
             
             "5F40" : "Compressed image template",
             "5F42" : "Address",
             "5F43" : "Compressed image template",
             
             "5F50" : "Date data recorded",
             "5F51" : "Name of person",
             "5F52" : "Telephone",
             "5F53" : "Address",
             
             "5F55" : "Date and time document personalized",
             "5F56" : "Serial number of personalization system",
             
             "60" : "Common data elements",
             "61" : "Template for MRZ data group",
             "63" : "Template for Finger biometric data group",
             "65" : "Template for digitized facial image",
             "67" : "Template for digitized Signature or usual mark",
             "68" : "Template for Machine Assisted Security - Encoded Data",
             "69" : "Template for Machine Assisted Security - Structure",
             "6A" : "Template for Machine Assisted Security - Substance",
             "6B" : "Template for Additional Personal Details",
             "6C" : "Template for Additional Document Details",
             "6D" : "Optional details",
             "6E" : "Reserved for future use",
             "70" : "Person to Notify",
             "75" : "Template for facial biometric data group",
             "76" : "Template for Iris (eye) biometric template",
             "77" : "EF.SOD (EF for security data)",
             "7F2E" : "Biometric data block (enciphered)",
             "7F60" : "Biometric Information Template",
             "7F61" : "Biometric Information Group Template",
             
             "80" : "ICAO header version",
             "81" : "Biometric Type",
             "82" : "Biometric subtype",
             "83" : "Creation date and time",
             "84" : "Validity period", # (revized in nov 2008)
             "85" : "Validity period", # (since 2008)
             "86" : "Creator of biometric reference data",
             "87" : "Format Owner",
             "88" : "Format Type",
             "89" : "Context specific tags",
             "8A" : "Context specific tags",
             "8B" : "Context specific tags",
             "8C" : "Context specific tags",
             "8D" : "Context specific tags",
             "8E" : "Context specific tags",
             "8F" : "Context specific tags",
             
             "90" : "Enciphered hash code",
             
             "A0" : "Context specific constructed data objects",
             
             "A1" : "Repeating template, 1 occurrence Biometric header",
             "A2" : "Repeating template, 2 occurrence Biometric header",
             "A3" : "Repeating template, 3 occurrence Biometric header",
             "A4" : "Repeating template, 4 occurrence Biometric header",
             "A5" : "Repeating template, 5 occurrence Biometric header",
             "A6" : "Repeating template, 6 occurrence Biometric header",
             "A7" : "Repeating template, 7 occurrence Biometric header",
             "A8" : "Repeating template, 8 occurrence Biometric header",
             "A9" : "Repeating template, 9 occurrence Biometric header",
             "AA" : "Repeating template, 10 occurrence Biometric header",
             "AB" : "Repeating template, 11 occurrence Biometric header",
             "AC" : "Repeating template, 12 occurrence Biometric header",
             "AD" : "Repeating template, 13 occurrence Biometric header",
             "AE" : "Repeating template, 14 occurrence Biometric header",
             "AF" : "Repeating template, 15 occurrence Biometric header",
             
             "B0" : "Repeating template, 0 occurrence Biometric header",
             "B1" : "Repeating template, 1 occurrence Biometric header",
             "B2" : "Repeating template, 2 occurrence Biometric header",
             "B3" : "Repeating template, 3 occurrence Biometric header",
             "B4" : "Repeating template, 4 occurrence Biometric header",
             "B5" : "Repeating template, 5 occurrence Biometric header",
             "B6" : "Repeating template, 6 occurrence Biometric header",
             "B7" : "Repeating template, 7 occurrence Biometric header",
             "B8" : "Repeating template, 8 occurrence Biometric header",
             "B9" : "Repeating template, 9 occurrence Biometric header",
             "BA" : "Repeating template, 10 occurrence Biometric header",
             "BB" : "Repeating template, 11 occurrence Biometric header",
             "BC" : "Repeating template, 12 occurrence Biometric header",
             "BD" : "Repeating template, 13 occurrence Biometric header",
             "BE" : "Repeating template, 14 occurrence Biometric header",
             "BF" : "Repeating template, 15 occurrence Biometric header",
#             }

# DOC9303-2 pg III-40
#tagMRZtoName = {
             "53" : "Optional Data",
             "59" : "Date of Expiry or valid Until Date",
             "02" : "Document Number",
             
             "5F02" : "Check digit - Optional data (ID-3 only)",
             "5F03" : "Document Type",
             "5F04" : "Check digit - Doc Number",
             "5F05" : "Check digit - DOB",
             "5F06" : "Expiry date",
             "5F07" : "Composite",
             
             "5F20" : "Issuing State or Organization",
             "5F2B" : "Date of birth",
             "5F2C" : "Nationality",
             
             "5F35" : "Sex",
             "5F57" : "Date of birth (6 digit)",
             
# From DG1 (information tags)
             "5F28" : "Issuing State or Organization",
             "5F5B" : "Name of Holder", # version 2006
             "5B" : "Name of Holder",   # version 2008
             "5A" : "Document Number",
                          
#            }        

# DOC9303-2 pg III-40
#tagRFUtoName = {
             "5F44" : "Country of entry/exit",
             "5F45" : "Date of entry/exit",
             "5F46" : "Port of entry/exit",
             "5F47" : "Entry/Exit indicator",
             "5F48" : "Length of stay",
             "5F49" : "Category (classification)",                          
             "5F4A" : "Inspector reference",
             "5F4B" : "Entry/Exit indicator",
             "71" : "Template for Electronic Visas", 
             "72" : "Template for Border Crossing Schemes",
             "73" : "Template for Travel Record Data Group",

# DataGroup             
             "60" : "Index",
             "61" : "MRZ",
             "75" : "Face",
             "63" : "Finger",
             "76" : "Eye (Iris)",
             "65" : "Portrait",
             "66" : "Reserved for Future Use",
             "67" : "Signature or Usual Mark",
             "68" : "Data Features",
             "69" : "Structure Features",
             "6A" : "Substance Features",
             "6B" : "Additional Personal Detail(s)",
             "6C" : "Additional Documents Detail(s)",
             "6D" : "Optional Details (Country Specific)",
             "6E" : "Reserved for Future Use",
             "6F" : "Active Authentication Public Key Info",
             "70" : "Person to Notify",
             "77" : "Security Object"             
            }     