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

import os

from analysis.analysis_models.dynamic_analysis import RenameEvent


class Ransomware:
    def __init__(self, dynamic_reports):
        self.dynamic_reports = dynamic_reports
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_file_extensions(self, data):
        """
        Checks for presence of certain file extensions which are used by ransomware
        to indicate encrypted files.
        """
        sha256 = data["file_hashes"]["sha256"]
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = RenameEvent.objects.filter(kernel_trace=kernel_trace)
        malicious_extensions = data.get("malicious_file_extensions", {})

        for obj in objs:
            # UTF-8 decoding should be sufficient
            newfile_path = obj.newfile_path.tobytes().decode("utf-8")
            newfile_path_extension = os.path.splitext(newfile_path)[1]
            if newfile_path_extension in malicious_extensions:
                dict_ = {
                    "file": sha256,
                    "detector": {
                        "name": type(self).__name__ + ":FileExtension",
                        "score": 70,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1486: Data Encrypted for Impact",
                        "description": f"Known {malicious_extensions[newfile_path_extension]}-related file extension found"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_file_renaming(self, data):
        """
        Checks for multiple file renaming events. Perhaps, it's a ransomware.
        If so, it will increase the score.
        """
        total_rename_events = 0
        num_interesting_rename_events = 0
        sha256 = data["file_hashes"]["sha256"]
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = RenameEvent.objects.filter(kernel_trace=kernel_trace)

        if objs:
            total_rename_events = len(objs)

        for obj in objs:
            oldfile_path = obj.oldfile_path.tobytes().decode("utf-8")
            # UTF-8 decoding should be sufficient
            newfile_path = obj.newfile_path.tobytes().decode("utf-8")
            oldfile_path_wo_ext = os.path.splitext(oldfile_path)[0]
            # The new path will basically be the old file along with
            # a ransomware variant-specific extension
            if oldfile_path_wo_ext in newfile_path:
                num_interesting_rename_events += 1

        # The decision to calculate interesting rename events to total rename events ratio is
        # based on the assumption that a potential ransomware will rename most of the files
        # in the system in the expected manner. Presence of many irrelevant rename events
        # will indicate that the malware may not be a ransomware, thus avoiding FPs.
        if total_rename_events > 0 and num_interesting_rename_events / total_rename_events > 0.8:
            dict_ = {
                "file": sha256,
                "detector": {
                    "name": type(self).__name__ + f":Generic",
                    "score": 30,
                    "author": "Nikhil Hegde <ka1do9>",
                    "mitre_attack": "T1486: Data Encrypted for Impact",
                    "description": "Multiple file renaming events detected"
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
        self.detect_file_renaming(data)
        self.detect_file_extensions(data)

        self.calc_score()
