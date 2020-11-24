import os
import ctypes
import time
from datetime import datetime, timedelta
from custom_exceptions import InsufficientPrivilegesException, RoundNotActiveException

class Engine:
    def __init__(self, round_name, start, length, vuln, local=False):
        if length <= 0: 
            raise ValueError('Length of a round cannot be less than or equal to 0.')
        if not vulns:
            raise ValueError('A round cannot have 0 vulnerabilities')

        self.round_name = round_name
        self.start = start
        self.stop = start + length
        self.vulns = {v: False for v in vulns}

        self.total_points = sum(v.points for v in vulns)
        self.current_points = 0

        self.total_vulns = len(vulns)
        self.current_vulns = 0

    def __validate(self):
        try:
            is_admin = os.geteuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        if not is_admin:
            raise InsufficientPrivilegesException('You must run this script as root/Administrator')

        curr_timestamp = datetime.now()
        if curr_timestamp < self.start:
            raise RoundNotActiveException('Round is not yet active/scoring.')
        elif curr_timestamp > self.stop:
            raise RoundNotActiveException('Round is over and is no longer scoring.')

    def __score(self):        
        points_scored, num_vulns, vulns_scored = 0, 0, []
        for v in vulns:
            if v.check():
                points_scored += v.points
                num_vulns += 1
                vulns_scored.append(True)
            else:
                vulns_scored.append(False)
        
        self.current_points = points_scored
        self.current_vulns = num_vulns

        return vulns_scored

    def run(self):
        self.__validate()
        self.__score()