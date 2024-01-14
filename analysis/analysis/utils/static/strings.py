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

import binary2strings as b2s
from analysis.analysis_models.static_analysis import Strings


def get_sample_strings(sample_path):
    """
    Extract printable strings from the sample.

    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: extracted strings and error message
    :rtype: list, str
    """
    all_strings = []
    err_msg = ""

    with open(sample_path, "rb") as f:
        # Get all printable strings with minimum length of 4
        for entry in b2s.extract_all_strings(f.read(), min_chars=4):
            string, _, _, _ = entry
            max_len = Strings._meta.get_field("string").max_length
            string = string[:max_len]
            if string not in all_strings:
                all_strings.append(string)

    return all_strings, err_msg
