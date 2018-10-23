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
p.doBasicAccessControl()
p.readCom()
```

But there are still conversion issues here and there in the code leading to trouble.
