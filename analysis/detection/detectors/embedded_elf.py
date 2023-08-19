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


class EmbeddedElf:
    def __init__(self, static_reports):
        self.static_reports = static_reports
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_embedded_elf(self, data):
        """
        Checks if the sample contains an embedded ELF file. If so, it will
        increase the score.
        """
        sha256 = data["file_hashes"]["sha256"]
        embedded_elf = self.static_reports.embedded_elf_offsets
        if embedded_elf:
            dict_ = {
                "file": sha256,
                "detector": {
                    "name": type(self).__name__ + ":EmbeddedElf",
                    "score": 30,
                    "author": "ELFEN",
                    "description": "Embedded ELF file detected",
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
        self.detect_embedded_elf(data)

        self.calc_score()
