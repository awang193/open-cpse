import re
from subprocess import Popen, PIPE, DEVNULL
from pathlib import Path


class Vulnerability:
    def __init__(self, description, points):
        self.description = description
        self.points = points
    
    def check(self):
        return True


class CompoundVulnerability(Vulnerability):
    def __init__(self, description, points, vulns):
        super().__init__(description, points)
        self.vulns = vulns
    
    def check(self):
        return all([v.check() for v in vulns])


class FileVulnerability(Vulnerability):
    def __init__(self, description, points, file, mode=1):
        super().__init__(description, points)
        self.file = Path(file)
        self.mode = mode
    
    def check(self):
        if self.mode:
            return self.file.is_file()
        else:
            return not self.file.is_file()


class StringInFileVulnerability(FileVulnerability):
    def __init__(self, description, points, file, string, mode=1):
        super().__init__(description, points, file)
        self.string = string
        self.mode = mode

    def check(self):
        with open(self.file) as f:
            if self.mode:
                return self.string in f.read()
            else:
                return self.string not in f.read()


class PatternInFileVulnerability(FileVulnerability):
    def __init__(self, description, points, file, patterns, mode=1):
        super().__init__(description, points, file)
        self.patterns = patterns
        self.mode = mode
    
    def check(self):
        with open(self.file) as f:
            text = f.read()
            matches = [(lambda p: re.search(p, text))(p) for p in self.patterns]
            if self.mode:
                return all(matches)
            else:
                return not any(matches)


class CustomCommandVulnerability(Vulnerability):
    def __init__(self, description, points, command, exit_code=0):
        super().__init__(description, points)
        self.command = command
        self.exit_code = exit_code
    
    def check(self):
        '''
        NOTES: 
        - mostly working
        - need to debug windows compatibility with commands like echo "test" | findstr "foo"
        '''
        split_command = [cmd.strip() for cmd in self.command.split('|')]
        
        if split_command:
            ps = Popen(split_command.pop(0), stdout=PIPE)
            while split_command:
                ps = Popen(split_command.pop(0), stdin=ps.stdout, stdout=PIPE)
            ps.communicate()
            ps.stdout.close()
            return ps.returncode == self.exit_code
        else:
            return True


# FAULTY OOP DESIGN, need to find a way to get os without creating engine first
class PackageVulnerability(Vulnerability):
    def __init__(self, description, points, package, version, mode=1):
        super().__init__(description, points)
        self.package = package
        self.version = version
        self.mode = mode
        
    def check(self):
        try:
            ps = Popen('dpkg -s ' + self.package, stdout=PIPE)
        except FileNotFoundError:
            ps = Popen('powershell.exe Get-Package ' + repr(self.package), stdout=PIPE)
        ps.communicate()
        return not ps.returncode == self.mode