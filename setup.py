# Copyright (c) 2010-2014 Greek Research and Technology Network S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from setuptools import setup

from vncauthproxy.version import __version__

setup(
    name="vncauthproxy",
    version=__version__,
    description="VNC authentication proxy",
    author="Synnefo development team",
    author_email="synnefo-devel@googlegroups.com",
    maintainer="Synnefo development team",
    maintainer_email="synnefo-devel@googlegroups.com",
    license="GPL2+",
    url="http://www.synnefo.org",
    packages=["vncauthproxy"],
    zip_safe=False,
    install_requires=[
        'python-daemon',
        'gevent>=1.0',
        'ws4py',
    ],
    entry_points={
        'console_scripts': [
            'vncauthproxy = vncauthproxy.proxy:main',
            'vncauthproxy-client = vncauthproxy.client:main',
            'vncauthproxy-passwd = vncauthproxy.passwd:main'
        ]
    }
)
