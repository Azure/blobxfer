# coding=utf-8
"""Tests for models upload"""

# stdlib imports
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
# module under test
import blobxfer.models.upload as upload


def test_localsourcepaths_files(tmpdir):
    tmpdir.mkdir('abc')
    tmpdir.join('moo.cow').write('z')
    abcpath = tmpdir.join('abc')
    abcpath.join('hello.txt').write('hello')
    abcpath.join('blah.x').write('x')
    abcpath.join('blah.y').write('x')
    abcpath.join('blah.z').write('x')
    abcpath.mkdir('def')
    defpath = abcpath.join('def')
    defpath.join('world.txt').write('world')
    defpath.join('moo.cow').write('y')

    a = upload.LocalSourcePath()
    a.add_includes('*.txt')
    a.add_includes(['moo.cow', '*blah*'])
    a.add_excludes('**/blah.x')
    a.add_excludes(['world.txt'])
    a.add_path(str(tmpdir))
    a_set = set()
    for file in a.files():
        sfile = str(file.parent_path / file.relative_path)
        a_set.add(sfile)

    assert len(a.paths) == 1
    assert str(abcpath.join('blah.x')) not in a_set
    assert str(defpath.join('world.txt')) in a_set
    assert str(defpath.join('moo.cow')) not in a_set

    b = upload.LocalSourcePath()
    b.add_includes(['moo.cow', '*blah*'])
    b.add_includes('*.txt')
    b.add_excludes(['world.txt'])
    b.add_excludes('**/blah.x')
    b.add_paths([pathlib.Path(str(tmpdir))])
    for file in a.files():
        sfile = str(file.parent_path / file.relative_path)
        assert sfile in a_set
