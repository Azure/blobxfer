from codecs import open
import os
import re
try:
    from setuptools import setup
except ImportError:  # noqa
    from distutils.core import setup
import sys

if sys.argv[-1] == 'publish':
    os.system('rm -rf blobxfer.egg-info/ build dist __pycache__/')
    os.system('python setup.py sdist bdist_wheel')
    os.unlink('README.rst')
    sys.exit()
elif sys.argv[-1] == 'upload':
    os.system('twine upload dist/*')
    sys.exit()
elif sys.argv[-1] == 'sdist' or sys.argv[-1] == 'bdist_wheel':
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
else:
    long_description = ''

with open('blobxfer/version.py', 'r', 'utf-8') as fd:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version')

packages = [
    'blobxfer',
    'blobxfer.blob',
    'blobxfer.blob.append',
    'blobxfer.blob.block',
    'blobxfer.blob.page',
    'blobxfer.crypto',
    'blobxfer.download',
    'blobxfer.file',
    'blobxfer_cli',
]

install_requires = [
    'azure-common==1.1.4',
    'azure-storage==0.34.0',
    'click==6.7',
    'cryptography>=1.7.2',
    'future==0.16.0',
    'python-dateutil==2.6.0',
    'ruamel.yaml==0.13.14',
]

if sys.version_info < (3, 4):
    install_requires.append('enum34')

if sys.version_info < (3, 5):
    install_requires.append('pathlib2')
    install_requires.append('scandir')

setup(
    name='blobxfer',
    version=version,
    author='Microsoft Corporation, Azure Batch and HPC Team',
    author_email='',
    description=(
        'Azure storage transfer tool and library with AzCopy-like features'),
    long_description=long_description,
    platforms='any',
    url='https://github.com/Azure/blobxfer',
    license='MIT',
    packages=packages,
    package_data={'blobxfer': ['LICENSE']},
    package_dir={'blobxfer': 'blobxfer', 'blobxfer_cli': 'cli'},
    entry_points={
        'console_scripts': 'blobxfer=blobxfer_cli.cli:cli',
    },
    zip_safe=False,
    install_requires=install_requires,
    tests_require=['pytest'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Utilities',
    ],
    keywords='azcopy azure storage blob files transfer copy smb cifs',
)
