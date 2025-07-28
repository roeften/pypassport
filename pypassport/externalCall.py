import subprocess
import os


class ExternalCallException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)


class ExternalCall():

    def toDisk(self, name, data=None):
        with open(name, "wb") as f:
            if data:
                f.write(data)

    def remFromDisk(self, name):
        try:
            os.remove(name)
        except BaseException:
            pass

    def execute(self, cmd):

        with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as res:
            out = res.stdout.read()
            err = res.stderr.read()

            if ((not out) and err):
                raise ExternalCallException(err)

            return out
