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

from setuptools import setup, find_packages
setup(
    name = "pypassport",
    version = "1.0",
    description='Python Biometric Passport API',
    author='Jean-Francois Houzard & Olivier Roger',
    author_email='jhouzard@gmail.com & folkenda@gmail.com',
    url='http://code.google.com/p/pypassport/downloads/list',
    packages = find_packages(),
    

    # Project uses reStructuredText, so ensure that the docutils get
    # installed or upgraded on the target machine
    install_requires = ['setuptools', 'pyCrypto', 'pyasn1', 'pyscard', 'PIL'],

    package_data = {'': ['*.py'],
                    'pypassport': ['README', 'LICENSE'],
                    },

    # metadata for upload to PyPI
    license = "LGPL",
    keywords = "mrtd passport pypassport",
)
