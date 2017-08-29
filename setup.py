from codecs import open
import re
try:
    from setuptools import setup
except ImportError:  # noqa
    from distutils.core import setup
import sys

if sys.argv[-1] == 'sdist' or sys.argv[-1] == 'bdist_wheel':
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
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
    'azure-storage==0.36.0',
    'bitstring==3.1.5',
    'click==6.7',
    'cryptography>=2.0.3',
    'future==0.16.0',
    'pathlib2==2.3.0;python_version<"3.5"',
    'python-dateutil==2.6.1',
    'requests==2.18.4',
    'ruamel.yaml==0.15.32',
    'scandir==1.5;python_version<"3.5"',
]

setup(
    name='blobxfer',
    version=version,
    author='Microsoft Corporation',
    author_email='',
    description='Azure storage transfer tool and library',
    platforms='any',
    url='https://github.com/Azure/blobxfer',
    license='MIT',
    long_description=long_description,
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
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Utilities',
    ],
    keywords=[
        'azure', 'storage', 'blob', 'files', 'transfer', 'copy', 'smb',
        'cifs', 'azcopy'
    ],
)
