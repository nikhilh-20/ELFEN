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

from django.contrib.postgres import fields
from web.models import SampleMetadata
from analysis.analysis_models.utils import *


class AntiAntiStaticAnalysis(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    elflepton = models.BooleanField(default=False,
                                    verbose_name="Headers fixed by ELFLepton")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class AntiStaticAnalysis(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    # Randomly chosen max_len
    readelf = models.CharField(max_length=1024, null=True,
                               verbose_name="Messages while parsing with readelf")
    pyelftools = models.CharField(max_length=1024, null=True,
                                  verbose_name="Messages while parsing with pyelftools")
    packers = models.CharField(max_length=1024, null=True, verbose_name="Packer")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class SampleFeatures(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT,
                               related_name="sample_features")
    os = models.CharField(max_length=32, null=True,
                          verbose_name="Operating system")
    arch = models.CharField(max_length=10, null=True,
                            verbose_name="Architecture")
    endian = models.CharField(choices=Endianness.choices, max_length=2, null=True,
                              verbose_name="Endianness")
    bit = models.CharField(choices=Bitness.choices, max_length=7, null=True,
                           verbose_name="Bitness")
    average_entropy = models.FloatField(null=True,
                                        verbose_name="Average entropy")
    highest_block_entropy = models.FloatField(null=True,
                                              verbose_name="Highest 256-byte block entropy")
    entry_point_bytes = models.BinaryField(max_length=20, null=True,
                                           verbose_name="Bytes at entry point address")
    num_sections = models.SmallIntegerField(null=True, verbose_name="Number of sections")
    num_segments = models.SmallIntegerField(null=True, verbose_name="Number of segments")
    num_symtab_symbols = models.SmallIntegerField(null=True,
                                                  verbose_name="Number of symbols in .symtab")
    num_dynsym_symbols = models.SmallIntegerField(null=True,
                                                  verbose_name="Number of symbols in .dynsym")
    filesize = models.BigIntegerField(null=True, verbose_name="File size (bytes)")
    lib_deps = fields.ArrayField(models.CharField(max_length=128), null=True,
                                 verbose_name="Library dependencies")
    stripped = models.BooleanField(null=True, verbose_name="Stripped")
    # Max filepath length in Linux == 4096
    interp = models.CharField(max_length=4096, null=True, verbose_name="Interpreter")
    packed = models.CharField(max_length=128, null=True, verbose_name="Packed")
    truncated = models.BooleanField(null=True, verbose_name="Truncated")
    compiler = models.CharField(max_length=64, null=True, verbose_name="Compiler")
    # I don't know of a hard length limit for a function name. So, randomly
    # setting to 1024
    imports = fields.ArrayField(models.CharField(max_length=1024), null=True,
                                verbose_name="Imports")
    exports = fields.ArrayField(models.CharField(max_length=1024), null=True,
                                verbose_name="Exports")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_bit_valid",
                check=models.Q(bit__in=Bitness.values)
            ),
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_endian_valid",
                check=models.Q(endian__in=Endianness.values)
            ),
        ]


class Strings(models.Model):
    string = models.CharField(max_length=2048, primary_key=True, verbose_name="String")
    sha256s = fields.ArrayField(models.CharField(max_length=64),
                                verbose_name="SHA256s of samples containing this string")


class ELFHeader(models.Model):
    # Using OneToOneField here so that each sample is associated with one
    # ELFHeader entry at most. This is especially useful for duplicate
    # submissions. Two submissions for one sample should still have only
    # one ELFHeader entry.
    sample = models.OneToOneField(SampleMetadata, on_delete=models.PROTECT)
    e_ident_magic = models.BinaryField(max_length=4, null=True, verbose_name="EI_MAG")
    e_ident_ei_class = models.CharField(max_length=12, null=True, verbose_name="EI_CLASS")
    e_ident_ei_data = models.CharField(max_length=11, null=True, verbose_name="EI_DATA")
    e_ident_ei_version = models.CharField(max_length=10, null=True, verbose_name="EI_VERSION")
    e_ident_ei_osabi = models.CharField(max_length=19, null=True, verbose_name="EI_OSABI")
    e_ident_ei_abiversion = models.PositiveSmallIntegerField(null=True,
                                                             verbose_name="EI_ABIVERSION")
    # With the current ELF specification, number of padding bytes == 7
    e_ident_ei_pad = models.BinaryField(max_length=7, null=True, verbose_name="EI_PAD")
    e_ident_ei_nident = models.SmallIntegerField(null=True, verbose_name="EI_NIDENT")
    e_type = models.CharField(max_length=7, null=True, verbose_name="e_type")
    e_machine = models.CharField(max_length=14, null=True, verbose_name="e_machine")
    e_version = models.CharField(max_length=10, null=True, verbose_name="e_version")
    e_entry = models.PositiveBigIntegerField(null=True, verbose_name="e_entry")
    e_phoff = models.PositiveBigIntegerField(null=True, verbose_name="e_phoff")
    e_shoff = models.PositiveBigIntegerField(null=True, verbose_name="e_shoff")
    e_flags = models.PositiveBigIntegerField(null=True, verbose_name="e_flags")
    e_ehsize = models.PositiveSmallIntegerField(null=True, verbose_name="e_ehsize")
    e_phentsize = models.PositiveSmallIntegerField(null=True, verbose_name="e_phentsize")
    e_phnum = models.PositiveSmallIntegerField(null=True, verbose_name="e_phnum")
    e_shentsize = models.PositiveSmallIntegerField(null=True, verbose_name="e_shentsize")
    e_shnum = models.PositiveSmallIntegerField(null=True, verbose_name="e_shnum")
    e_shstrndx = models.PositiveSmallIntegerField(null=True, verbose_name="e_shstrndx")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class ELFProgramHeader(models.Model):
    # Using OneToOneField here so that each sample is associated with one
    # ELFProgramHeader entry at most. This is especially useful for duplicate
    # submissions. Two submissions for one sample should still have only one
    # ELFProgramHeader entry.
    sample = models.OneToOneField(SampleMetadata, on_delete=models.PROTECT)
    p_type = fields.ArrayField(models.CharField(max_length=15), null=True,
                               verbose_name="p_type")
    p_offset = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                 verbose_name="p_offset")
    p_flags = fields.ArrayField(models.PositiveIntegerField(), null=True,
                                verbose_name="p_flags")
    p_vaddr = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                verbose_name="p_vaddr")
    p_paddr = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                verbose_name="p_paddr")
    p_filesz = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                 verbose_name="p_filesz")
    p_memsz = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                verbose_name="p_memsz")
    p_align = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                verbose_name="p_align")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class ELFSectionHeader(models.Model):
    # Using OneToOneField here so that each sample is associated with one
    # ELFSectionHeader entry at most. This is especially useful for duplicate
    # submissions. Two submissions for one sample should still have only one
    # ELFSectionHeader entry.
    sample = models.OneToOneField(SampleMetadata, on_delete=models.PROTECT)
    sh_name = fields.ArrayField(models.PositiveIntegerField(), null=True,
                                verbose_name="sh_name")
    # I don't know of a hard length limit for a section name. So, randomly
    # setting to 2048
    sh_name_str = fields.ArrayField(models.BinaryField(max_length=2048), null=True,
                                    verbose_name="sh_name (string)")
    sh_type = fields.ArrayField(models.CharField(max_length=15), null=True,
                                verbose_name="sh_type")
    sh_flags = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                 verbose_name="sh_flags")
    sh_addr = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                verbose_name="sh_addr")
    sh_offset = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                  verbose_name="sh_offset")
    sh_size = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                verbose_name="sh_size")
    sh_link = fields.ArrayField(models.PositiveIntegerField(), null=True,
                                verbose_name="sh_link")
    sh_info = fields.ArrayField(models.PositiveIntegerField(), null=True,
                                verbose_name="sh_info")
    sh_addralign = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                     verbose_name="sh_addralign")
    sh_entsize = fields.ArrayField(models.PositiveBigIntegerField(), null=True,
                                   verbose_name="sh_entsize")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class CapaCapabilities(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    base_address = models.PositiveBigIntegerField(null=True)
    rules = fields.ArrayField(models.CharField(max_length=1024), null=True)
    namespaces = fields.ArrayField(models.CharField(max_length=1024), null=True)
    addresses = fields.ArrayField(fields.ArrayField(models.PositiveBigIntegerField()), null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_status_valid",
                check=models.Q(status__in=TaskStatusChoices.values)
            )
        ]


class PrintableStrings(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    strs = fields.ArrayField(models.CharField(max_length=4096), null=True,
                             verbose_name="Strings")
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class StaticAnalysisReports(models.Model):
    elfheader = models.ForeignKey(ELFHeader, on_delete=models.CASCADE, null=True)
    elfprogheader = models.ForeignKey(ELFProgramHeader, on_delete=models.CASCADE,
                                      null=True)
    elfsectionheader = models.ForeignKey(ELFSectionHeader, on_delete=models.CASCADE,
                                         null=True)
    # Store only the offsets of the embedded ELF file in the parent ELF file
    embedded_elf_offsets = fields.ArrayField(models.PositiveBigIntegerField(),
                                             null=True)
    capa = models.ForeignKey(CapaCapabilities, on_delete=models.CASCADE,
                             null=True)
    samplefeatures = models.ForeignKey(SampleFeatures, on_delete=models.CASCADE,
                                       null=True)
    staticantianalysis = models.ForeignKey(AntiStaticAnalysis, on_delete=models.CASCADE,
                                           null=True)
    staticantiantianalysis = models.ForeignKey(AntiAntiStaticAnalysis, on_delete=models.CASCADE,
                                               null=True)
    strings = models.ForeignKey(PrintableStrings, on_delete=models.CASCADE, null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_status_valid",
                check=models.Q(status__in=TaskStatusChoices.values)
            )
        ]
