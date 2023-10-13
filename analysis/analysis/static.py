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
import json
import logging
from celery import shared_task
from analysis.models import TaskMetadata
from analysis.analysis_models.static_analysis import *
import analysis.analysis.utils.static.parse_elf as parse_elf
from analysis.analysis.anti_analysis.static import check_tool_warnings,\
     check_if_packed
from analysis.analysis.utils.utils import update_object_fields
from analysis.analysis.utils.static.capa import get_capa_capabilities
from analysis.analysis.utils.static.features import get_sample_features
from analysis.analysis.utils.static.strings import get_sample_strings

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def apply_strings(sample, sample_path):
    """
    Extract printable strings from the sample. They are dumped to the disk and
    to the DB.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: Printable strings object
    :rtype: analysis.analysis_models.static_analysis.PrintableStrings
    """
    sha256 = sample.sha256
    printable_strings, _ = PrintableStrings.objects.get_or_create(sample=sample)
    printable_strings.status = TaskStatus.IN_PROGRESS
    printable_strings.save(update_fields=["status"])
    strings, err_msg = get_sample_strings(sample_path)

    if err_msg:
        printable_strings.error_msg = err_msg
        printable_strings.errors = True
        printable_strings.save(update_fields=["error_msg", "errors"])

    if strings is None:
        return None
    LOG.debug(f"Extracted {len(strings)} strings from {sha256}")

    update_object_fields(printable_strings, [
        ("strs", strings),
    ])
    printable_strings.status = TaskStatus.COMPLETE
    printable_strings.save(update_fields=["strs", "status"])

    # Write strings to disk
    with open(os.path.join(os.path.dirname(sample_path), "strings.json"), "w") as f:
        json.dump({"strs": strings}, f)

    create_objs = []
    update_objs = []
    for s in strings:
        try:
            existing_obj = Strings.objects.get(string=s)
            sha256s = existing_obj.sha256s

            # Update unique values
            if sha256 not in sha256s:
                sha256s.append(sha256)

            update_object_fields(existing_obj, [
                ("sha256s", sha256s),
            ])
            update_objs.append(existing_obj)
        except Strings.DoesNotExist:
            create_objs.append(Strings(sha256s=[sha256], string=s))

    LOG.debug("Updating strings objects in database.")
    Strings.objects.bulk_update(update_objs, fields=["sha256s"],
                                batch_size=1000)
    LOG.debug("Creating strings objects in database.")
    Strings.objects.bulk_create(create_objs)

    return printable_strings


def apply_feature_extractor(sample, sample_path):
    """
    This function extracts certain features from the sample and updates
    SampleFeatures task object. These features include:

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: Sample features object
    :rtype: analysis.analysis_models.static_analysis.SampleFeatures
    """
    features = SampleFeatures.objects.create(sample=sample,
                                             status=TaskStatus.IN_PROGRESS)
    sample_features, err_msg = get_sample_features(sample_path)

    if sample_features is None:
        # Error in sample features extraction
        features.error_msg = err_msg
        features.errors = True
        features.status = TaskStatus.ERROR
        features.save(update_fields=["error_msg", "errors", "status"])
        return features

    update_object_fields(features, [
        ("average_entropy", sample_features["average_entropy"]),
        ("highest_block_entropy", sample_features["highest_block_entropy"]),
        ("entry_point_bytes", sample_features["entry_point_bytes"]),
        ("packed", sample_features["packed"]),
        ("truncated", sample_features["is_truncated"]),
        ("stripped", sample_features["stripped"]),
        ("interp", sample_features["interp"]),
        ("num_segments", sample_features["num_segments"]),
        ("num_sections", sample_features["num_sections"]),
        ("num_symtab_symbols", sample_features["num_symtab_symbols"]),
        ("num_dynsym_symbols", sample_features["num_dynsym_symbols"]),
        ("filesize", sample_features["filesize"]),
        ("lib_deps", sample_features["lib_deps"]),
        ("os", sample_features["os"]),
        ("arch", sample_features["arch"]),
        ("endian", sample_features["endian"]),
        ("bit", sample_features["bit"]),
        ("compiler", sample_features["compiler"]),
        ("imports", sample_features["imports"]),
        ("exports", sample_features["exports"]),
    ])
    features.status = TaskStatus.COMPLETE
    features.save()
    return features


def apply_capa(sample, sample_path):
    """
    This function applies capa tool on the sample and updates CapaCapabilities
    task object. It skips files of size >5MB to avoid spending too much time here.
    TODO: Remove filesize restriction

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: Capa capabilities object
    :rtype: analysis.analysis_models.static_analysis.CapaCapabilities
    """
    capa = CapaCapabilities.objects.create(sample=sample,
                                           status=TaskStatus.IN_PROGRESS)

    try:
        if os.path.getsize(sample_path) <= 5242880:
            base_address, rule_names, rule_namespaces, rule_match_addrs, err_msg = \
                get_capa_capabilities(sample_path)
        else:
            base_address, rule_names, rule_namespaces, rule_match_addrs, err_msg = \
                None, None, None, None, "Sample size is greater than 5MB, skipping capa analysis."
    except (KeyError, TypeError) as err:
        base_address, rule_names, rule_namespaces, rule_match_addrs, err_msg = \
            None, None, None, None, f"Something went wrong while running capa: {err}"

    if all(i is None for i in (base_address, rule_names, rule_namespaces, rule_match_addrs)) is True:
        # Error in capa capabilities extraction
        capa.error_msg = err_msg
        capa.errors = True
        capa.status = TaskStatus.ERROR
        capa.save(update_fields=["error_msg", "errors", "status"])
        return capa

    padded_rule_match_addrs = [[]]
    if rule_match_addrs:
        # Rule matches are stored in a nested ArrayField in PostgreSQL DB, so it
        # requires the arrays to be rectangular
        max_matches = max(len(lst) for lst in rule_match_addrs)
        padded_rule_match_addrs = [[lst[i] if i < len(lst) else 0
                                   for i in range(max_matches)]
                                   for lst in rule_match_addrs]

    capa.base_address = base_address
    capa.rules = rule_names
    capa.namespaces = rule_namespaces
    capa.addresses = padded_rule_match_addrs
    capa.status = TaskStatus.COMPLETE
    capa.save()
    return capa


def detect_anti_analysis_techniques(sample, sample_path):
    """
    This function detects anti-analysis techniques implemented in the sample.
    Anomalies detected by certain tools are also considered anti-analysis.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param sample_path: Full on-disk path to the sample
    :type sample_path: str
    :return: anti-analysis object and anti-anti-analysis object
    :rtype: analysis.analysis_models.static_analysis.AntiStaticAnalysis,
            analysis.analysis_models.static_analysis.AntiStaticAnalysis
    """
    LOG.debug(f"Detecting anti-analysis techniques in {sample_path}")
    aa = AntiStaticAnalysis.objects.create(sample=sample,
                                           status=TaskStatus.IN_PROGRESS)
    aaa = AntiAntiStaticAnalysis.objects.create(sample=sample,
                                                status=TaskStatus.IN_PROGRESS)

    packer = check_if_packed(sample_path)
    if packer == "unknown":
        packer = None
    anomalies, msg = check_tool_warnings(sample_path)

    if anomalies:
        # In presence of anomalous ELF headers, elflepton will have
        # previously (analysis.tasks.py:L89) tried to fix them.
        aaa.elflepton = True
        aaa.status = TaskStatus.COMPLETE
        aaa.save()
    for tool_name in msg:
        setattr(aa, tool_name, msg[tool_name])

    aa.packers = packer
    aa.status = TaskStatus.COMPLETE
    aa.save()
    return aa, aaa


def parse_elf_header(sample, basic_info):
    """
    This function parses the ELF header in the sample and updates the DB.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param basic_info: Sample object containing parsed ELF properties.
    :type basic_info: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    :return: ELF header object
    :rtype: analysis.analysis_models.static_analysis.ELFHeader
    """
    elfheader, _ = ELFHeader.objects.get_or_create(sample=sample)
    elfheader.status = TaskStatus.IN_PROGRESS
    elfheader.save(update_fields=["status"])

    update_object_fields(elfheader, [
        ("e_ident_magic", basic_info.ei_mag),
        ("e_ident_ei_class", basic_info.ei_class),
        ("e_ident_ei_data", basic_info.ei_data),
        ("e_ident_ei_version", basic_info.ei_version),
        ("e_ident_ei_osabi", basic_info.ei_osabi),
        ("e_ident_ei_abiversion", basic_info.ei_abiversion),
        ("e_ident_ei_pad", basic_info.ei_pad),
        ("e_ident_ei_nident", basic_info.ei_nident),
        ("e_type", basic_info.e_type),
        ("e_machine", basic_info.e_machine),
        ("e_version", basic_info.e_version),
        ("e_entry", basic_info.e_entry),
        ("e_phoff", basic_info.e_phoff),
        ("e_shoff", basic_info.e_shoff),
        ("e_flags", basic_info.e_flags),
        ("e_ehsize", basic_info.e_ehsize),
        ("e_phentsize", basic_info.e_phentsize),
        ("e_phnum", basic_info.e_phnum),
        ("e_shentsize", basic_info.e_shentsize),
        ("e_shnum", basic_info.e_shnum),
        ("e_shstrndx", basic_info.e_shstrndx),
    ])
    elfheader.status = TaskStatus.COMPLETE
    elfheader.save()
    return elfheader


def parse_elf_program_header(sample, basic_info):
    """
    This function parses the ELF program header in the sample and updates
    the DB.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param basic_info: Sample object containing parsed ELF properties.
    :type basic_info: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    :return: ELF program header object
    :rtype: analysis.analysis_models.static_analysis.ELFProgramHeader
    """
    elfprogheader, _ = ELFProgramHeader.objects.get_or_create(sample=sample)
    elfprogheader.status = TaskStatus.IN_PROGRESS
    elfprogheader.save(update_fields=["status"])

    # program_headers is a list of dict. Each dict is a program header entry.
    program_headers = basic_info.get_program_headers()

    update_object_fields(elfprogheader, [
        ("p_type", [phdr["p_type"] for phdr in program_headers]),
        ("p_offset", [phdr["p_offset"] for phdr in program_headers]),
        ("p_flags", [phdr["p_flags"] for phdr in program_headers]),
        ("p_vaddr", [phdr["p_vaddr"] for phdr in program_headers]),
        ("p_paddr", [phdr["p_paddr"] for phdr in program_headers]),
        ("p_filesz", [phdr["p_filesz"] for phdr in program_headers]),
        ("p_memsz", [phdr["p_memsz"] for phdr in program_headers]),
        ("p_align", [phdr["p_align"] for phdr in program_headers]),
    ])
    elfprogheader.status = TaskStatus.COMPLETE
    elfprogheader.save()
    return elfprogheader


def parse_elf_section_header(sample, basic_info):
    """
    This function parses the ELF section header in the sample and updates
    the DB.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param basic_info: Sample object containing parsed ELF properties.
    :type basic_info: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    :return: ELF section header object
    :rtype: analysis.analysis_models.static_analysis.ELFSectionHeader
    """
    elfsectionheader, _ = ELFSectionHeader.objects.get_or_create(sample=sample)
    elfsectionheader.status = TaskStatus.IN_PROGRESS
    elfsectionheader.save(update_fields=["status"])

    # section_headers is a list of dict. Each dict is a section header entry.
    section_headers = basic_info.get_section_headers()

    update_object_fields(elfsectionheader, [
        ("sh_name", [shdr["sh_name"] for shdr in section_headers]),
        ("sh_name_str", [shdr["sh_name_str"] for shdr in section_headers]),
        ("sh_type", [shdr["sh_type"] for shdr in section_headers]),
        ("sh_flags", [shdr["sh_flags"] for shdr in section_headers]),
        ("sh_addr", [shdr["sh_addr"] for shdr in section_headers]),
        ("sh_offset", [shdr["sh_offset"] for shdr in section_headers]),
        ("sh_size", [shdr["sh_size"] for shdr in section_headers]),
        ("sh_link", [shdr["sh_link"] for shdr in section_headers]),
        ("sh_info", [shdr["sh_info"] for shdr in section_headers]),
        ("sh_addralign", [shdr["sh_addralign"] for shdr in section_headers]),
        ("sh_entsize", [shdr["sh_entsize"] for shdr in section_headers]),
    ])
    elfsectionheader.status = TaskStatus.COMPLETE
    elfsectionheader.save()
    return elfsectionheader


@shared_task(queue="static_analysis")
def start_analysis(context):
    """
    This task is called by analysis.tasks, and it kicks off a series of static
    analysis steps.

    :param context: A dictionary containing username, user-submitted form
                    parameters and other analysis options/metadata.
    :type context: dict
    :return: None
    :rtype: None
    """
    LOG.debug(f"Starting static analysis")
    dirpath = context["dirpath"]
    submission_id = os.path.basename(os.path.normpath(dirpath))
    sample_sha256 = context["file_hashes"]["sha256"]
    sample = SampleMetadata.objects.get(sha256=sample_sha256)
    additional_files = context["additional_files"]

    # Check if sample was previously fixed.
    if context.get("fixed_sample_path", None):
        LOG.debug(f"Sample was fixed. Getting fixed sample path")
        sample_path = context["fixed_sample_path"]
    else:
        LOG.debug(f"Sample was not fixed. Getting original path")
        sample_path = context["sample_path"]

    LOG.debug(f"Static analysis execution context: "
              f"dirpath={dirpath}, submission_id={submission_id}, "
              f"sample_sha256={sample_sha256}, additional_files={additional_files}, "
              f"sample_path={sample_path}")

    parent_task = TaskMetadata.objects.get(uuid=submission_id)
    LOG.debug(f"Got parent task: {parent_task} from TaskMetadata table")
    task_reports = parent_task.taskreports
    LOG.debug(f"Got task reports: {task_reports} from TaskReports table")

    # Create StaticAnalysisReports task object
    static_analysis_reports = StaticAnalysisReports.objects.create(
        status=TaskStatus.IN_PROGRESS,
    )
    LOG.debug(f"Created StaticAnalysisReports object: {static_analysis_reports}")
    task_reports.static_reports = static_analysis_reports
    task_reports.save(update_fields=["static_reports"])

    # If any anti-analysis techniques exist in the original sample,
    # retrieve messages or warnings output by vulnerable tools
    aa, aaa = detect_anti_analysis_techniques(sample, context["sample_path"])
    LOG.debug(f"Got anti-analysis techniques object: {aa}")
    static_analysis_reports.staticantianalysis = aa
    static_analysis_reports.staticantiantianalysis = aaa
    static_analysis_reports.save(update_fields=["staticantianalysis",
                                                "staticantiantianalysis"])

    # Parse sample. This may be the original sample or fixed sample
    LOG.debug(f"Trying to parse {sample_path} with PyelftoolsParser")
    basic_info = parse_elf.PyelftoolsParser(sample_path)

    # Get number of embedded ELF files
    LOG.debug(f"Getting offsets of embedded ELF files")
    embedded_elf = parse_elf.get_embedded_elf(sample_path)
    static_analysis_reports.embedded_elf_offsets = [entry[1] for entry in embedded_elf]
    static_analysis_reports.save(update_fields=["embedded_elf_offsets"])

    # Extract headers from sample
    elfheader = parse_elf_header(sample, basic_info)
    LOG.debug(f"Extracted ELF header from sample: {elfheader}")
    static_analysis_reports.elfheader = elfheader
    static_analysis_reports.save(update_fields=["elfheader"])

    elfprogheader = parse_elf_program_header(sample, basic_info)
    LOG.debug(f"Extracted ELF program header from sample: {elfprogheader}")
    static_analysis_reports.elfprogheader = elfprogheader
    static_analysis_reports.save(update_fields=["elfprogheader"])

    elfsectionheader = parse_elf_section_header(sample, basic_info)
    LOG.debug(f"Extracted ELF section header from sample: {elfsectionheader}")
    static_analysis_reports.elfsectionheader = elfsectionheader
    static_analysis_reports.save(update_fields=["elfsectionheader"])

    # Extract features/characteristics from the original/fixed sample
    samplefeatures = apply_feature_extractor(sample, sample_path)
    LOG.debug(f"Extracted sample features from sample: {samplefeatures}")
    static_analysis_reports.samplefeatures = samplefeatures
    static_analysis_reports.save(update_fields=["samplefeatures"])

    # Apply capa on original/fixed sample
    capa = apply_capa(sample, sample_path)
    LOG.debug(f"Applied capa rules: {capa} to sample")
    static_analysis_reports.capa = capa
    static_analysis_reports.save(update_fields=["capa"])

    # Extract readable strings from original/fixed sample
    printable_strings = apply_strings(sample, sample_path)
    static_analysis_reports.strings = printable_strings
    LOG.debug(f"Extracted printable strings from sample")

    # Mark static analysis reports task complete
    static_analysis_reports.status = TaskStatus.COMPLETE
    static_analysis_reports.save(update_fields=["status", "strings"])
    LOG.debug(f"Static analysis complete")
