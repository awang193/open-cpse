import os
import subprocess
from pathlib import Path

class Vulnerability:
    def __init__(self, description, points):
        self.description = description
        self.points = points
    
    def check(self):
        return True


class FileVulnerability(Vulnerability):
    def __init__(self, description, points, file, string, mode=1):
        super().__init__(description, points)
        self.file = file
        self.string = string
        self.mode = mode

    def check(self):
        with open(self.file) as f:
            if self.mode:
                return self.string in f.read()
            else:
                return self.string not in f.read()


class CustomCommandVulnerability(Vulnerability):
    def __init__(self, description, points, command, exit_code):
        super().__init__(description, points)
        self.command = command
        self.exit_code = exit_code
    
    def check(self):
        split_command = [tuple(cmd.split()) for cmd in self.command.split('|')]
        
        if split_command:
            ps = subprocess.Popen(split_command.pop(0), stdout=subprocess.PIPE)
            while split_command:
                cmd = split_command.pop(0)
                print('DEBUG: cmd', cmd)
                ps = subprocess.Popen(cmd, stdin=ps.stdout, stdout=subprocess.PIPE)
            ps.communicate()
            print('DEBUG: final exit code', ps.returncode)
            return ps.returncode == self.exit_code
        else:
            return True
        