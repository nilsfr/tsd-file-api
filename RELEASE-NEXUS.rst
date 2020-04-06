================
Release to Nexus
================

The release proccess is based on the official documentation for `distributing packages`_.

Create a `~/.pypirc`_ file to upload to USIT Nexus repository::

    [distutils]
    index-servers =
        usit-internal
        pypi

    [usit-internal]
    repository: https://repo.usit.uio.no/nexus/repository/pypi-internal/
    username: somenexususer
    password: somepassword

    [pypi]

Create a bindary and a source release and use twine_ to upload the packages. Also sign the
packages using a gpg_ key::

    python setup.py sdist bdist_wheel
    twine upload -r usit-internal -s dist/*

.. _distributing packages: https://packaging.python.org/tutorials/distributing-packages/
.. _~/.pypirc: https://docs.python.org/3/distutils/packageindex.html#pypirc
.. _twine: https://github.com/pypa/twine
.. _gpg: https://gnupg.org/
