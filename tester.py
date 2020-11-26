from engine import Engine
from vulnerabilities import *

vulnerabilities = [
    Vulnerability('basic vuln, always scored', 1),
    FileVulnerability('check if fileexists.txt exists', 2, 'tests/fileexists.txt'),
    FileVulnerability('check if doesntexist.txt does not exist', 3, 'tests/doesnotexist.txt', mode=0),
    StringInFileVulnerability('check if foo in stringinfile.txt', 4, 'tests/stringinfile.txt', 'foo'),
    StringInFileVulnerability('check if bar not in stringinfile.txt', 4, 'tests/stringinfile.txt', 'bar', mode=0),
    PatternInFileVulnerability('check if pattern in file', 5, 'engine.py', ['time', 'import']),
    PatternInFileVulnerability('check if pattern not in file', 6, 'engine.py', ['nonexistent', 'foobar'], mode=0),
    CustomCommandVulnerability('command with no pipes', 7, 'echo "yummee"'),
    CustomCommandVulnerability('command with pipes', 8, 'echo "yummee" | grep "yum"'),
    PackageVulnerability('check if geodash is installed', 9, 'Geometry Dash', 1),
    PackageVulnerability('check if random name package is removed', 10, 'asdfas', 1, mode=0)
]

e = Engine('testround', 'Linux', 1, 1, vulnerabilities, local=True)

res = e.score()

print(res)