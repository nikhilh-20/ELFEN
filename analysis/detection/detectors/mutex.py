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
import json

from django.conf import settings
from analysis.analysis_models.dynamic_analysis import OpenEvent


class Mutex:
    def __init__(self, dynamic_reports):
        self.mutex_fpath = os.path.join(settings.BASE_DIR, "rsrc", "detection", "mutex.json")
        self.family = []
        self.dynamic_reports = dynamic_reports
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def _check_match(self, mutex_path, mutexes):
        malware_family = mutexes.get(mutex_path, None)
        if malware_family:
            dict_ = {
                "file": None,
                "detector": {
                    "name": type(self).__name__ + f":KnownMutex_{malware_family}",
                    "score": 70,
                    "author": "Nikhil Hegde <ka1do9>",
                    "description": f"Detected creation of known mutex for {malware_family} family"
                }
            }
            if dict_ not in self.triggered_detectors:
                self.family.append(malware_family)
                self.triggered_detectors.append(dict_)

    def detect_known_mutex(self):
        """
        Checks for the creation of known mutex. If so, it will
        increase the score.
        """
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = OpenEvent.objects.filter(kernel_trace=kernel_trace)

        # Read known mutexes JSON if OpenEvents are found
        if objs:
            with open(self.mutex_fpath, "r") as f:
                mutexes = json.load(f)

        for obj in objs:
            file_path = obj.file_path
            if file_path:
                # Not sure if UTF-8 is the only applicable encoding
                file_path = file_path.tobytes().decode("utf-8")
                self._check_match(file_path, mutexes)

    def calc_score(self):
        scores = []
        for entry in self.triggered_detectors:
            detector = entry["detector"]
            s = detector["score"]
            if s:
                scores.append(s)

        self.score = max(scores) if scores else 0

    def detect(self, data):
        self.detect_known_mutex()

        self.calc_score()
