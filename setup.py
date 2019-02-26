from codecs import open
import re
try:
    from setuptools import setup
except ImportError:  # noqa
    from distutils.core import setup
import sys

if 'sdist' in sys.argv or 'bdist_wheel' in sys.argv:
    long_description = open('README.md', 'r', 'utf-8').read()
else:
    long_description = ''

with open('blobxfer/version.py', 'r', 'utf-8') as fd:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
        fd.read(), re.MULTILINE).group(1)

if not version or len(version) == 0:
    raise RuntimeError('Cannot find version')

packages = [
    'blobxfer',
    'blobxfer.models',
    'blobxfer.operations',
    'blobxfer.operations.azure',
    'blobxfer.operations.azure.blob',
    'blobxfer_cli',
]

install_requires = [
    'azure-storage-blob~=1.5.0',
    'azure-storage-file~=1.4.0',
    'bitstring~=3.1.5',
    'click~=7.0',
    'cryptography~=2.5',
    'future~=0.17.1',
    'pathlib2>=2.3.3;python_version<"3.5"',
    'python-dateutil~=2.8.0',
    'requests~=2.21.0',
    'ruamel.yaml~=0.15.88',
    'scandir>=1.9.0;python_version<"3.5"',
]

setup(
    name='blobxfer',
    version=version,
    author='Microsoft Corporation',
    author_email='',
    description='Azure storage transfer tool and data movement library',
    platforms='any',
    url='https://github.com/Azure/blobxfer',
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
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
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
    ],
    keywords=[
        'azure', 'storage', 'blob', 'files', 'transfer', 'copy', 'smb',
        'cifs', 'blobxfer', 'azcopy'
    ],
)
