#!/usr/bin/env python

from setuptools import setup

setup(
    name='tsd-file-api',
    version='2.0.1.dev1',
    description='A REST API for handling files and json',
    author='Leon du Toit',
    author_email='l.c.d.toit@usit.uio.no',
    url='https://github.com/leondutoit/tsd-file-api',
    packages=['tsdfileapi'],
    package_data={
        'tsdfileapi': [
            'tests/*.py',
            'tests/*.pem',
            'data/.csv.*',
            'data/.tar.*',
            'data/resume*',
            'data/s*',
            'data/r*',
            'data/an*',
            'data/ex*',
            'data/tsd/p11/export/fi*',
            'data/tsd/p11/export/bl*',
            'data/tsd/p11/export/.~lock*',
            'data/tsd/p11/export/data-folder/s*',
            'config/file-api-config.yaml.example',
            'config/file-api.service',
        ]
    },
    scripts=[
        'scripts/generic-chowner',
        'scripts/file-api',
    ],
    entry_points={
        "console_scripts": [
            "tsdfileapi = tsdfileapi.api:main",
        ]
    },
    install_requires=[
        "jwcrypto==0.6.0",
        "pyyaml==5.1.2",
        "tornado==6.0.3",
        "click==7.0",
        "requests==2.22.0",
        "pretty-bad-protocol==3.1.1",
        "sqlalchemy==1.3.8",
        "psycopg2-binary==2.8.3",
        "python-magic==0.4.15",
        "humanfriendly==4.18",
        "progress==1.5",
        "pandas==0.25.1",
        "termcolor==1.1.0",
        "libnacl==1.7.1",
        "pika==1.1.0",
    ],
    extras_require={
        "dev": ["wheel", "twine"],
    },
)
