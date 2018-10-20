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

class Logger(object):
    def __init__(self, name):
        self._listeners = []
        self._name = name
        
    def register(self, fct):
        """the listener gives the method he want as callback"""
        self._listeners.append(fct)
        
    def unregister(self, listener):
        self._listeners.remove(listener)
        
    def log(self, msg, name=None):
        if name != None:
            n = name
        else: n = self._name
        
        for listenerFct in self._listeners:
            listenerFct(n, msg)
            
    