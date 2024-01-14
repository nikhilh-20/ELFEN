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


class Yara:
    def __init__(self, static_reports):
        self.static_reports = static_reports
        self.family = []
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_main_sample(self, data):
        """
        Checks if the main sample triggered any yara. If so, it will
        increase the score.
        """
        matches, scores, desc, authors, mitre_attack = [], [], [], [], []
        sample_path = data["sample_path"]
        compiled_rules = data["compiled_yara_rules"]

        if sample_path:
            sample_matches_ = compiled_rules.match(sample_path)
            if sample_matches_:
                matches = [f"{m.namespace}:{m.rule}" for m in sample_matches_]
                scores = [m.meta.get("score", 0) for m in sample_matches_]
                desc = [m.meta.get("description", "") for m in sample_matches_]
                authors = [m.meta.get("author", "") for m in sample_matches_]
                mitre_attack = [m.meta.get("mitre_attack", "") for m in sample_matches_]
                self.family.extend([m.meta["family"] for m in sample_matches_
                                    if m.meta.get("family", None)])

            if matches:
                for r, s, d, a, m in zip(matches, scores, desc, authors, mitre_attack):
                    dict_ = {
                        "file": data["file_hashes"]["sha256"],
                        "detector": {
                            "name": type(self).__name__ + f":{r}",
                            "score": s,
                            "author": a,
                            "mitre_attack": m,
                            "description": d,
                        }
                    }
                    if dict_ not in self.triggered_detectors:
                        self.triggered_detectors.append(dict_)

    def detect_additional_files(self, data):
        """
        Checks if the main sample triggered any yara. If so, it will
        increase the score.
        """
        dirpath = data["dirpath"]
        additional_files = data["additional_files"]
        compiled_rules = data["compiled_yara_rules"]

        for f in additional_files:
            file_path = os.path.join(dirpath, f)
            file_matches_ = compiled_rules.match(file_path)
            if file_matches_:
                matches = [f"{m.namespace}:{m.rule}" for m in file_matches_]
                scores = [m.meta.get("score", 0) for m in file_matches_]
                desc = [m.meta.get("description", "") for m in file_matches_]
                authors = [m.meta.get("author", "") for m in file_matches_]
                mitre_attack = [m.meta.get("mitre_attack", "") for m in file_matches_]
                self.family.extend([m.meta["family"] for m in file_matches_
                                    if m.meta.get("family", None)])

                for r, s, d, a, m in zip(matches, scores, desc, authors, mitre_attack):
                    dict_ = {
                        "file": f,
                        "detector": {
                            "name": type(self).__name__ + f":{r}",
                            "score": s,
                            "author": a,
                            "mitre_attack": m,
                            "description": d,
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
        self.detect_main_sample(data)
        self.detect_additional_files(data)

        self.calc_score()
