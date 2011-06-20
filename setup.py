#!/usr/bin/env python

from setuptools import setup

setup(
    name="vncauthproxy",
    version="1.0",
    description="VNC authentication proxy",
    author="Apollon Oikonomopoulos",
    author_email="apollon@noc.grnet.gr",
    license="GPL2+",
    url="http://code.grnet.gr/projects/vncauthproxy",
    packages=["vncauthproxy"],
    install_requires=[
        'daemon',
        'gevent',
    ],
    scripts=['vncauthproxy.py'],
)
