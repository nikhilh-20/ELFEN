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
import shutil
import pathlib
import zipfile
import logging

from random import choice
from string import ascii_letters

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class MemYara:
    def __init__(self, dynamic_reports):
        self.dynamic_reports = dynamic_reports
        self.family = []
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_memory_dumps(self, data):
        """
        Checks if the memory dumps, if any triggered any yara. If so, it will
        increase the score.
        """
        dynamic_analysis_dir = data["dynamic_analysis_dir"]
        compiled_rules = data["compiled_yara_rules"]

        # Extract dropped files to this temp directory
        tmpdir = os.path.join("/tmp", "".join(choice(ascii_letters) for _ in range(8)))
        dropped_files_zip = os.path.join(dynamic_analysis_dir, "memdump.zip")
        if os.path.isfile(dropped_files_zip):
            with zipfile.ZipFile(dropped_files_zip, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)
            dropped_files = [str(e) for e in list(pathlib.Path(tmpdir).rglob("*")) if e.is_file()]

            for file_path in dropped_files:
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
                            "file": None,
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

        # Delete tmpdir
        if os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir)

    def detect_dropped_files(self, data):
        """
        Checks if the dropped files, if any triggered any yara. If so, it will
        increase the score.
        """
        dynamic_analysis_dir = data["dynamic_analysis_dir"]
        compiled_rules = data["compiled_yara_rules"]

        # Extract dropped files to this temp directory
        tmpdir = os.path.join("/tmp", "".join(choice(ascii_letters) for _ in range(8)))
        dropped_files_zip = os.path.join(dynamic_analysis_dir, "dropped.zip")
        if os.path.isfile(dropped_files_zip):
            with zipfile.ZipFile(dropped_files_zip, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)
            dropped_files = [str(e) for e in list(pathlib.Path(tmpdir).rglob("*")) if e.is_file()]

            for file_path in dropped_files:
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
                            "file": os.path.basename(file_path),
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

        # Delete tmpdir
        if os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir)

    def calc_score(self):
        scores = []
        for entry in self.triggered_detectors:
            detector = entry["detector"]
            s = detector["score"]
            if s:
                scores.append(s)

        self.score = max(scores) if scores else 0

    def detect(self, data):
        self.detect_memory_dumps(data)
        self.detect_dropped_files(data)

        self.calc_score()
