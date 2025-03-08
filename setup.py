#!/usr/bin/env python

from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

setup(
    name='mullvadshal',
    version='1.0.0',
    description='Mullvadshål is utomated server-hopping for Mullvad VPN for WireGuard and Linux',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Addvilz',
    author_email='mrtreinis@gmail.com',
    url='https://github.com/Addvilz/mullvadshal',
    download_url='https://github.com/Addvilz/mullvadshal',
    license='Apache 2.0',
    platforms='UNIX',
    packages=find_packages(),
    py_modules=['mullvadshal'],
    install_requires=[
        'requests>=2.31.0',
        'cryptography>=43.0.3',
        'argparse',  # argparse is included in Python stdlib, no version required
    ],
    entry_points={
        'console_scripts': [
            'mullvadshal = mullvadshal.main:main',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python :: 3 :: Only'
    ],
)
