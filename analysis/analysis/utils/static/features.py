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
import struct
import logging
import bintropy
import subprocess
import capa.features.extractors.elf

from analysis.analysis.anti_analysis.static import check_if_packed
from analysis.analysis.utils.static.parse_elf import get_basic_info

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def _align_as_per_model(sample_info):
    """
    The web.models.SampleMetadata model requires some fields to be in a
    certain format. This function aligns values in the required manner.

    :param sample_info: Sample object containing parsed ELF properties.
    :type sample_info: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    :return: Updated sample object
    :rtype: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    """
    # Align ei_class values as per "bit" field in SampleMetadata model.
    if sample_info.ei_class == "ELFCLASS64":
        sample_info.ei_class = "bits_64"
    elif sample_info.ei_class == "ELFCLASS32":
        sample_info.ei_class = "bits_32"
    else:
        sample_info.ei_class = None

    # Align ei_data values as per "endian" field in SampleMetadata model.
    if sample_info.ei_data == "ELFDATA2LSB":
        sample_info.ei_data = "LE"
    elif sample_info.ei_data == "ELFDATA2MSB":
        sample_info.ei_data = "BE"
    else:
        sample_info.ei_data = None

    return sample_info


def get_sample_features(sample_path):
    """
    Extract a bunch of features from the sample.

    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: Sample features and error message, if any
    :rtype: dict, str
    """
    err_msg = ""
    is_truncated = None
    num_entry_point_bytes_to_read = 20
    entry_point_bytes = b""

    try:
        highest_block_entropy, average_entropy = bintropy.bintropy(sample_path,
                                                                   decide=False)
    except ValueError as err:
        LOG.debug(f"bintropy failed: {err}")
        highest_block_entropy, average_entropy = None, None

    packer = check_if_packed(sample_path)

    # Have to align certain fields as required by SampleFeatures model.
    basic_info, _, _ = get_basic_info(sample_path)
    basic_info = _align_as_per_model(basic_info)

    # imports and exports are each a list of strings.
    imports, exports = basic_info.get_imports_exports()

    with open(sample_path, "rb") as f:
        try:
            sample_os = capa.features.extractors.elf.detect_elf_os(f)
        except (struct.error, UnicodeDecodeError, ValueError) as err:
            LOG.error(f"Error while detecting OS using capa: {err}")
            sample_os = None

        try:
            sample_arch = capa.features.extractors.elf.detect_elf_arch(f)
        except (struct.error, UnicodeDecodeError, ValueError) as err:
            LOG.error(f"Error while detecting architecture using capa: {err}")
            sample_arch = None

        if basic_info.e_entry:
            # Convert virtual address to raw offset.
            entry_pt_load = None
            for phdr in basic_info.get_program_headers():
                # Only PT_LOAD segments are loaded into memory
                if phdr["p_type"] == "PT_LOAD":
                    # Check if entry point is in current PT_LOAD segment
                    if phdr["p_vaddr"] <= basic_info.e_entry <= phdr["p_vaddr"] + phdr["p_memsz"]:
                        entry_pt_load = phdr["p_vaddr"]
                        break

            if entry_pt_load:
                raw_offset = basic_info.e_entry - entry_pt_load
                is_truncated = False
                if raw_offset >= basic_info.filesize:
                    # Entry point raw address is beyond the end of file.
                    is_truncated = True

                f.seek(raw_offset)
                entry_point_bytes = f.read(num_entry_point_bytes_to_read)

    # elfinfo is an open-source Go library
    out = subprocess.run(["elfinfo", sample_path], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if out.stderr or out.returncode != 0:
        compiler = "unknown"
    else:
        compiler = out.stdout.decode().strip()

    return {
        "average_entropy": average_entropy,
        "highest_block_entropy": highest_block_entropy,
        "entry_point_bytes": entry_point_bytes,
        "packed": packer,
        "is_truncated": is_truncated,
        "stripped": basic_info.is_stripped(),
        "interp": basic_info.get_interp(),
        "num_symtab_symbols": basic_info.get_num_symtab_symbols(),
        "num_dynsym_symbols": basic_info.get_num_dynsym_symbols(),
        "num_sections": basic_info.e_shnum,
        "num_segments": basic_info.e_phnum,
        "filesize": basic_info.filesize,
        "lib_deps": basic_info.get_lib_deps(),
        "os": sample_os,
        "arch": sample_arch,
        "endian": basic_info.ei_data,
        "bit": basic_info.ei_class,
        "compiler": compiler,
        "imports": imports,
        "exports": exports,
    }, err_msg
