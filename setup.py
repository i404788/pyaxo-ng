try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import versioneer
import pathlib
HERE = pathlib.Path(__file__).parent
README = (HERE / "README.rst").read_text()

setup(
    name='pyaxo_ng',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    long_description=README,
    long_description_content_type="text/x-rst",
    description='Python implementation of the Axolotl ratchet protocol',
    author='Ferris Kwaijtaal',
    url='https://github.com/i404788/pyaxo-ng',
    license="GPLv3",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    py_modules=[
        'pyaxo_ng'
    ],
    install_requires=[
        'pycryptodome>=3.9.8',
        'pynacl>=1.4.0',
        'diskcache>=4.1.0'
    ],
    tests_require=[
        'pytest',
    ],
)
