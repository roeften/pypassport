import json

from pypassport import epassport, reader


def calculateChecksum(value):
    weighting = [7, 3, 1]
    characterWeight = {
        '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7,
        '8': 8, '9': 9, '<': 0, 'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14,
        'F': 15, 'G': 16, 'H': 17, 'I': 18, 'J': 19, 'K': 20, 'L': 21, 'M': 22,
        'N': 23, 'O': 24, 'P': 25, 'Q': 26, 'R': 27, 'S': 28, 'T': 29, 'U': 30,
        'V': 31, 'W': 32, 'X': 33, 'Y': 34, 'Z': 35
    }
    counter = 0
    result = 0
    for x in value:
        result += characterWeight[str(x)] * weighting[counter % 3]
        counter += 1
    return str(result % 10)


def calculateMRZ(passportNumber, DOB, expiry):
    """
    DOB and expiry are formatted as YYMMDD
    """
    passportCheck = calculateChecksum(passportNumber)
    DOBCheck = calculateChecksum(DOB)
    expiryCheck = calculateChecksum(expiry)
    mrzNumber = passportNumber + passportCheck + DOB + DOBCheck + expiry + expiryCheck
    mrzCheck = calculateChecksum(mrzNumber).zfill(2)
    mrz = passportNumber + passportCheck + "XXX" + DOB + DOBCheck + "X" + expiry + expiryCheck + "<<<<<<<<<<<<<<" + mrzCheck
    return mrz


def encode_binary(obj):
    if isinstance(obj, dict):
        return {k: encode_binary(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [encode_binary(item) for item in obj]
    elif isinstance(obj, bytes):
        # Convert to a string like '\xff\xd8\xff\xe0'
        return obj.decode('latin1').encode('unicode_escape').decode('ascii')
    else:
        return obj


#                                   XXXXXXXXX        YYMMDD           YYMMDD
MRZ = calculateMRZ(passportNumber="123456789", DOB="840104", expiry="220229")

print("Calculated MRZ is " + MRZ)

r = reader.ReaderManager().waitForCard()

ep = epassport.EPassport(r, MRZ)

ep.readPassport()

#   Save Photo
photo = ep["75"]["A1"]["5F2E"]
with open(MRZ + "-photo.jpg", "wb") as f:
    f.write(photo)
    print("Saved photo.")

#   Save Photo Metadata
photoMeta = ep["75"]["A1"]["meta"]
#   Convert to JSON-safe format
photoMeta = encode_binary(photoMeta)
json_str = json.dumps(photoMeta, indent=3)
with open(MRZ + "-photo.json", "w") as f:
    f.write(json_str)
    print("Saved photo metadata.")

#   Save Passport Metadata
meta = ep["61"]
#   Convert to JSON-safe format
meta = encode_binary(meta)
json_str = json.dumps(meta, indent=3)
with open(MRZ + ".json", "w") as f:
    f.write(json_str)
    print("Saved passport metadata.")
