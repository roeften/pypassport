# pypassport
pypassport for python3

Tested working so far:

```
from pypassport.reader import ReaderManager
from pypassport.epassport import EPassport, mrz
r = ReaderManager()
reader = r.waitForCard()
p = EPassport(reader,"YOURMRZINFO")
p.register(print)
p.setCSCADirectory("C:\\TEMP")
p.doBasicAccessControl()
p.doActiveAuthentication()

p['DG2']

```

The picture can be read and saved as well:

```
....

import io
from PIL import Image

passportimage = p['DG2']['A1']['5F2E']
imgfp = io.BytesIO(passportimage)
img = Image.open(imgfp)
img.save("c:\\TEMP\\passport.png")

```
If you find any conversion issues pls let me know.
