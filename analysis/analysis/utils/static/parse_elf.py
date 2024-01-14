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
import lepton
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFParseError, ELFError
import analysis.analysis.anti_analysis.static as static_anti_analysis

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class PyelftoolsParser:
    """
    This ELF parser leverages https://pypi.org/project/pyelftools
    """

    def __init__(self, sample_path):
        self.obj = None
        self.interp = None
        self.err_msg = ""
        self.sample_path = sample_path
        self.num_symtab_symbols = 0
        self.num_dynsym_symbols = 0
        self.imports = []
        self.exports = []
        self.needed_libs = []
        LOG.debug(f"Parsing {sample_path} with PyelftoolsParser")
        with open(sample_path, "rb") as f:
            # If this parser has been called, there should be no
            # exception/error here
            self.obj = ELFFile(f)

            # A stripped ELF binary does not contain SHT_SYMTAB section
            try:
                LOG.debug("Checking if ELF sample is stripped")
                self.stripped = self.obj.get_section_by_name(".symtab") is None
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                self.stripped = None

            # ELF interpreter.
            # Packed programs / .so may not have ".interp" section.
            try:
                LOG.debug("Extracting interpreter string from ELF sample")
                interp_section = self.obj.get_section_by_name(".interp")
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                interp_section = None
            if interp_section:
                self.interp = interp_section.data().decode().strip("\x00")

            # Find number of symbols in .symtab section if it exists
            self.num_symtab_symbols = 0
            try:
                LOG.debug("Extracting number of .symtab symbols from ELF sample")
                symtab_section = self.obj.get_section_by_name(".symtab")
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                symtab_section = None
            if symtab_section:
                self.num_symtab_symbols = len(list(symtab_section.iter_symbols()))

            # Find number of symbols in .dynsym section
            try:
                LOG.debug("Getting .dynsym section from ELF sample")
                dynsym_section = self.obj.get_section_by_name(".dynsym")
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                dynsym_section = None
            if dynsym_section:
                LOG.debug("Extracting number of .dynsym symbols from ELF sample")
                self.num_dynsym_symbols = len(list(dynsym_section.iter_symbols()))
                LOG.debug("Extracting imports and exports from ELF sample")
                for sym in dynsym_section.iter_symbols():
                    if sym.entry["st_shndx"] == "SHN_UNDEF":
                        if sym.name:
                            self.imports.append(sym.name)
                    else:
                        if sym.name:
                            self.exports.append(sym.name)

            # Find DT_NEEDED libraries
            try:
                LOG.debug("Extracting DT_NEEDED libs from ELF sample")
                dynamic_section = self.obj.get_section_by_name(".dynamic")
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                dynamic_section = None
            if dynamic_section:
                self.needed_libs = [tag.needed
                                    for tag in dynamic_section.iter_tags()
                                    if tag.entry.d_tag == "DT_NEEDED"]

        self._elf_header_extract()
        self._elf_program_header_extract()
        self._elf_section_header_extract()

    def _elf_header_extract(self):
        """
        Determines values of selected fields in the ELF header

        :return: None
        :rtype: None
        """
        LOG.debug("Extracting ELF header fields")
        # The length of the e_ident array is specified in the ELF specification
        # https://man7.org/linux/man-pages/man5/elf.5.html
        self.nident = 16

        # With the current specification, number of padding bytes == 7
        padding_length = 7
        # Why 9, you ask? That's the total length of other fields in the
        # e_ident array that exist before the padding bytes.
        start_padding_bytes_index = 9
        with open(self.sample_path, "rb") as f:
            f.seek(start_padding_bytes_index)
            self.padding_bytes = f.read(padding_length)

    def _elf_program_header_extract(self):
        """
        Extracts all entries from the ELF program header table.

        :return: None
        :rtype: None
        """
        LOG.debug("Extracting ELF program header fields")
        self.program_headers = []
        with open(self.sample_path, "rb") as f:
            obj = ELFFile(f)
            try:
                for p in obj.iter_segments():
                    phdr = {
                        "p_type": p.header.p_type, "p_offset": p.header.p_offset,
                        "p_flags": p.header.p_flags, "p_vaddr": p.header.p_vaddr,
                        "p_paddr": p.header.p_paddr, "p_filesz": p.header.p_filesz,
                        "p_memsz": p.header.p_memsz, "p_align": p.header.p_align
                    }
                    self.program_headers.append(phdr)
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                return

    def _elf_section_header_extract(self):
        """
        Extract all fields from the ELF section header table, if available.

        :return: None
        :rtype: None
        """
        LOG.debug("Extracting ELF section header fields")
        self.section_headers = []
        with open(self.sample_path, "rb") as f:
            obj = ELFFile(f)
            e_shstrndx = obj.header.e_shstrndx
            try:
                shdrs = list(obj.iter_sections())
            except (ELFParseError, ELFError) as err:
                self.err_msg += f"{err},"
                return
            if not shdrs:
                # Stripped ELF
                return

            shdrs_names = shdrs[e_shstrndx].data()
            for s in shdrs:
                sh_name = s.header.sh_name
                shdr = {
                    "sh_name": sh_name,
                    "sh_name_str": shdrs_names[sh_name: shdrs_names.find(b"\0", sh_name)],
                    "sh_type": s.header.sh_type, "sh_flags": s.header.sh_flags,
                    "sh_addr": s.header.sh_addr, "sh_offset": s.header.sh_offset,
                    "sh_size": s.header.sh_size, "sh_link": s.header.sh_link,
                    "sh_info": s.header.sh_info,
                    "sh_addralign": s.header.sh_addralign,
                    "sh_entsize": s.header.sh_entsize
                }
                self.section_headers.append(shdr)

    def is_stripped(self):
        return self.stripped

    def get_interp(self):
        return self.interp

    def get_program_headers(self):
        return self.program_headers

    def get_section_headers(self):
        return self.section_headers

    def get_imports_exports(self):
        return self.imports, self.exports

    @property
    def filesize(self):
        return os.path.getsize(self.sample_path)

    def get_num_symtab_symbols(self):
        return self.num_symtab_symbols

    def get_num_dynsym_symbols(self):
        return self.num_dynsym_symbols

    def get_lib_deps(self):
        return self.needed_libs

    @property
    def ei_mag(self):
        return struct.pack('B' * len(self.obj.header.e_ident.EI_MAG), *self.obj.header.e_ident.EI_MAG)

    @property
    def ei_class(self):
        return self.obj.header.e_ident.EI_CLASS

    @ei_class.setter
    def ei_class(self, value):
        self.obj.header.e_ident.EI_CLASS = value

    @property
    def ei_data(self):
        return self.obj.header.e_ident.EI_DATA

    @ei_data.setter
    def ei_data(self, value):
        self.obj.header.e_ident.EI_DATA = value

    @property
    def ei_version(self):
        return self.obj.header.e_ident.EI_VERSION

    @property
    def ei_osabi(self):
        return self.obj.header.e_ident.EI_OSABI

    @property
    def ei_abiversion(self):
        return self.obj.header.e_ident.EI_ABIVERSION

    @property
    def ei_pad(self):
        return self.padding_bytes

    @property
    def ei_nident(self):
        return self.nident

    @property
    def e_type(self):
        return self.obj.header.e_type

    @e_type.setter
    def e_type(self, value):
        self.obj.header.e_type = value

    @property
    def e_machine(self):
        return self.obj.header.e_machine

    @property
    def e_version(self):
        return self.obj.header.e_version

    @property
    def e_entry(self):
        return self.obj.header.e_entry

    @property
    def e_phoff(self):
        return self.obj.header.e_phoff

    @property
    def e_shoff(self):
        return self.obj.header.e_shoff

    @property
    def e_flags(self):
        return self.obj.header.e_flags

    @property
    def e_ehsize(self):
        return self.obj.header.e_ehsize

    @property
    def e_phentsize(self):
        return self.obj.header.e_phentsize

    @property
    def e_phnum(self):
        return self.obj.header.e_phnum

    @property
    def e_shentsize(self):
        return self.obj.header.e_shentsize

    @property
    def e_shnum(self):
        return self.obj.header.e_shnum

    @property
    def e_shstrndx(self):
        return self.obj.header.e_shstrndx


def get_basic_info(sample_path):
    """
    This function determines a set of basic characteristics of the sample. These
    are determined using https://pypi.org/project/pyelftools. In some cases,
    the ELF header may be corrupted in such a way that parsers fail but the sample
    successfully executes. In other words, an ELF binary may leverage anti-analysis
    techniques to make open-source ELF parsing tools less effective. In such cases,
    the headers are fixed (by elflepton) and then parsed.

    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: Sample characteristics object, sample path, anti-analysis messages
    :rtype: analysis.analysis.utils.static.parse_elf.PyelftoolsParser, str, dict
    """
    LOG.debug(f"Getting basic info from {sample_path}")
    # If there is any anti-analysis technique used, the sample path is updated to
    # the fixed sample, and not the submitted sample.
    sample_path, msg = static_anti_analysis.check_elf_header_anomalies(sample_path)

    if sample_path is None:
        LOG.error(f"ELF binary not in a state to be parsed.")
        return None, sample_path, msg

    try:
        LOG.debug(f"Trying to parse {sample_path} with PyelftoolsParser")
        sample_obj = PyelftoolsParser(sample_path)
    except AttributeError as err:
        LOG.error(f"Error while parsing with PyelftoolsParser: {err}")
        return None, sample_path, msg

    return sample_obj, sample_path, msg


def get_embedded_elf(sample_path):
    """
    This function leverages elflepton to extract any ELF files embedded within the
    submitted sample. This extraction is not 100% reliable because it is very
    difficult to reliably determine an embedded ELF file's size.

    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: Embedded ELF files. Each tuple contains the embedded ELF file content
             and the offset where it was found in the parent ELF binary.
    :rtype: list of tuples
    """
    LOG.debug(f"Extracting embedded ELF from {sample_path} using lepton")
    try:
        with open(sample_path, "rb") as f:
            elf_file = lepton.lepton.ELFFile(f)
    except lepton.utils.exceptions.UnsupportedArchError:
        return []

    return elf_file.get_embedded_elf()
