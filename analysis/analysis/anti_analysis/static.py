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
import logging
import bintropy
import subprocess
from lepton import lepton
import elftools.common.exceptions
from elftools.elf.elffile import ELFFile
from analysis.analysis_models.static_analysis import AntiStaticAnalysis

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def fix_headers(sample_path):
    """
    Leverage https://github.com/nikhilh-20/lepton to fix ELF headers and write
    the updated file to disk.

    :param sample_path: Full on-disk path to submitted sample
    :type sample_path: str
    :return: Fixed sample path
    :rtype: str
    """
    LOG.debug(f"Attempting to fix headers for {sample_path}")
    new_sample_path = sample_path + "_fixed"
    with open(sample_path, "rb") as f:
        elf_file = lepton.ELFFile(f, new_header=True)

    new_data = elf_file.reconstruct_file()

    with open(new_sample_path, "wb") as f:
        f.write(new_data)

    return new_sample_path


def check_if_packed(sample_path):
    """
    This function checks if the sample is packed.

    :param sample_path: Full on-disk to the sample
    :type sample_path: str
    :return: Packer, if detected.
    :rtype: str
    """
    LOG.debug(f"Checking if {sample_path} is packed")
    # Use entropy to check if the sample is packed. It leverages
    # https://github.com/packing-box/bintropy. The threshold values are slightly
    # more relaxed than specified in the associated paper. This modification is
    # based purely on observation in my test samples.
    entropy_packed = bintropy.bintropy(sample_path,
                                       threshold_average_entropy=6.6,
                                       threshold_highest_entropy=7.1)

    if entropy_packed:
        return "High entropy"

    return "unknown"


def check_tool_warnings(sample_path):
    """
    This function leverages readelf/pyelftools to parse the sample and record
    warnings, if any. These warnings indicate corruption, or atleast anomalies.

    :param sample_path: Full on-disk path to submitted sample
    :type sample_path: str
    :return: Flag to indicate presence of anomalies, Recorded tool warnings
    :rtype: bool, dict
    """
    msg = {}
    corruption = False

    LOG.debug(f"Checking for anomalies in {sample_path} using readelf")
    # readelf outputs errors messages in presence of corrupted ELF headers
    max_len = AntiStaticAnalysis._meta.get_field("readelf").max_length
    out = subprocess.run(["readelf", "-h", sample_path], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if out.stderr or out.returncode != 0:
        msg["readelf"] = out.stderr.decode("utf-8")[:max_len]
        corruption = True

    LOG.debug(f"Checking for anomalies in {sample_path} using pyelftools")
    # Sometimes pyelftools fails in presence of corrupted ELF headers
    max_len = AntiStaticAnalysis._meta.get_field("pyelftools").max_length
    with open(sample_path, "rb") as f:
        try:
            ELFFile(f)
        except (OSError, elftools.common.exceptions.ELFError, TypeError) as err:
            msg["pyelftools"] = f"pyelftools: {str(err)}"[:max_len]
            corruption = True

    return corruption, msg


def check_elf_header_corruption(sample_path):
    """
    Check if there is any corruption/anti-analysis techniques used in the
    submitted sample. If any, fix it, write updated file to disk and return
    new sample path.

    :param sample_path: Full on-disk path to submitted sample
    :type sample_path: str
    :return: Fixed sample path and anti-analysis message, if any
    :rtype: str, dict
    """
    LOG.debug(f"Checking for ELF header corruption in {sample_path}")
    anti_analysis, msg = check_tool_warnings(sample_path)

    if anti_analysis:
        LOG.debug(f"Found anti-analysis techniques in {sample_path}")
        if sample_path.endswith("_fixed"):
            LOG.debug(f"Sample {sample_path} already fixed. Skipping.")
            new_sample_path = sample_path
        else:
            new_sample_path = fix_headers(sample_path)
    else:
        LOG.debug(f"No anti-analysis techniques found in {sample_path}")
        new_sample_path = sample_path

    return new_sample_path, msg
