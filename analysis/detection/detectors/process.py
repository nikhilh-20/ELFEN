"""
Copyright (C) 2023  Nikhil Ashok Hegde (@ka1do9)

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

from analysis.analysis_models.dynamic_analysis import PrctlEvent, ExecveEvent


class Process:
    def __init__(self, dynamic_reports):
        self.dynamic_reports = dynamic_reports
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_process_name_change(self):
        """
        Checks for the presence of process name changes. If so, it will
        increase the score.
        """
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = PrctlEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            option = obj.option
            # https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h#L56
            if option == 15:
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":NameChange",
                        "score": 30,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1036: Masquerading",
                        "description": "Detects process name change through prctl()"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_uptime_process_execve(self):
        """
        Checks for the execution of "uptime" command in an ExecveEvent. If so,
        it will increase the score.
        """
        target_cmd = b"uptime"
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = ExecveEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            arg1 = obj.arg1.tobytes()
            arg2 = obj.arg2.tobytes()
            if arg1 == target_cmd or arg2 == target_cmd:
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":UptimeExecve",
                        "score": 30,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1497: Virtualization/Sandbox Evasion",
                        "description": "Detects \"uptime\" command execution"
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
        self.detect_process_name_change()
        self.detect_uptime_process_execve()

        self.calc_score()
