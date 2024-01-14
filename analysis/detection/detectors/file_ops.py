"""
Copyright (C) 2023-2024 Nikhil Ashok Hegde (@ka1do9)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import logging

from analysis.analysis_models.dynamic_analysis import OpenEvent

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class FileOps:
    def __init__(self, dynamic_reports):
        self.dynamic_reports = dynamic_reports
        self.family = []
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_bash_history_access(self):
        """
        Checks access to .bash_history file in various locations
        """
        bash_history_locations = [
            b"/var/www/.bash_history", b"/var/.bash_history",
            b"/home/.bash_history", b"/root/.bash_history",
            b"/usr/sbin/.bash_history", b"/bin/.bash_history",
            b"/dev/.bash_history", b"/bin/.bash_history",
            b"/var/spool/mail/.bash_history"
        ]
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = OpenEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            file_path = obj.file_path.tobytes()
            if file_path in bash_history_locations:
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":BashHistoryAccess",
                        "score": 30,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1552.003: Unsecured Credentials: Bash History",
                        "description": "Detects access to .bash_history file "
                                       "that contains Bash shell commands history"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_ssh_private_keys_access(self):
        """
        Checks access to SSH private keys for multiple algorithms
        """
        ssh_private_keys_locations = [
            b"/root/.ssh/id_rsa", b"/root/.ssh/id_dsa", b"/root/.ssh/id_ed25519",
            b"/root/.ssh/id_ecdsa"
        ]
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = OpenEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            file_path = obj.file_path.tobytes()
            if file_path in ssh_private_keys_locations:
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":SSHPrivateKeysAccess",
                        "score": 30,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1552.004: Unsecured Credentials: Private Keys",
                        "description": "Detects access to SSH private keys"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_user_accounts_info_access(self):
        """
        Checks access to /etc/passwd which contains user account information.
        """
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = OpenEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            file_path = obj.file_path.tobytes()
            if file_path == b"/etc/passwd":
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":UserAccountsInfoAccess",
                        "score": 10,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1003.008: OS Credential Dumping: /etc/passwd and /etc/shadow",
                        "description": "Detects access to /etc/passwd file "
                                       "that contains user accounts information"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def calc_score(self):
        scores = []
        for entry in self.triggered_detectors:
            detector = entry["detector"]
            s = detector["score"]
            if s:
                scores.append(s)

        self.score = max(scores) if scores else 0

    def detect(self, data):
        self.detect_bash_history_access()
        self.detect_ssh_private_keys_access()
        self.detect_user_accounts_info_access()

        self.calc_score()
