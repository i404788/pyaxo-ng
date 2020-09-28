try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import versioneer


setup(
    name='pyaxo-ng',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='Python implementation of the Axolotl ratchet protocol',
    author='Ferris Kwaijtaal',
    url='https://github.com/i404788/pyaxo-ng',
    py_modules=[
        'pyaxo'
    ],
    install_requires=[
        'passlib>=1.7.2',
        'pynacl>=1.4.0',
        'diskcache>=4.1.0'
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
)
