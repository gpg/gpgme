#!/usr/bin/env python

import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

__author__ = 'Ben McGinnes <ben@adversary.org>'
__version__ = '0.0.1'

packages = [
    'gpygme',
    'gpygme.gnupg',
    'gpygme.gpgsm'
]

if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist upload')
    sys.exit()

setup(
    name='GPyGME',
    version=__version__,
    install_requires=['cffi>=1.0.2'],
    author='Ben McGinnes',
    author_email='ben@adversary.org',
    license=open('COPYING.LESSER').read(),
    license=open('COPYING').read(),
    url='http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gpgme.git;a=summary',
    keywords='gpg gnupg openpgp api rest-like json encryption signing',
    description='Actively maintained, pure Python wrapper and API for the \
    GPGME cryptographic engine C API.  Provides Python modules for Python \
    3 and a stand alone API for developers using any other language.',
    long_description=open('README.org').read() + '\n\n' +
        open('FAQ.org').read(),
    include_package_data=True,
    packages=packages,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: LGPL 2.1+',
        'License :: OSI Approved :: GPL 2.0+',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: API',
        'Topic :: Security :: Cryptography',
        'Topic :: Security :: Cryptography :: Encryption',
        'Topic :: Security :: Cryptography :: Decryption',
        'Topic :: Security :: Cryptography :: Digital Signing',
        'Topic :: Security :: Cryptography :: Digital Signature Validation',
        'Topic :: Security :: Cryptography :: Authentication',
        'Topic :: Internet'
    ]
    # extras_require={
    #     'security': ['pyOpenSSL'],
    #     'library': ['cython']
    # },
)
