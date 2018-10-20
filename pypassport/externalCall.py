import subprocess, os

class ExternalCallException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class ExternalCall(object):
    
    def toDisk(self, name, data=None):
        f = open(name, "wb")
        if data: f.write(data)
        f.close()
        
    def remFromDisk(self, name):
        try:
            os.remove(name)
        except:
            pass
        
    def execute(self, cmd):
        
        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = res.stdout.read()
        err = res.stderr.read()
        
        if ((not out) and err):
            raise ExternalCallException(err)
        
        return out