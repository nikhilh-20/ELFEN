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
import tlsh
import logging
import datetime
import importlib
from django.conf import settings

from analysis.models import TaskMetadata, TaskReports
from analysis.enum import TaskStatus
from analysis.detection.detection import check_detection
import analysis.analysis.utils.static.parse_elf as parse_elf

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def _align_as_per_model(sample_info):
    """
    The web.models.SampleMetadata model requires some fields to be in a certain
    format. This function formats values in the required manner.

    :param sample_info: Sample object containing parsed ELF properties as
                        attributes
    :type sample_info: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    :return: Updated sample object
    :rtype: analysis.analysis.utils.static.parse_elf.PyelftoolsParser
    """
    LOG.debug(f"Aligning e_type values as per SampleMetadata model")
    # Align e_type values as per "bintype" field in SampleMetadata model.
    if sample_info.e_type == "ET_NONE":
        sample_info.e_type = None
    elif sample_info.e_type in ("ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE"):
        sample_info.e_type = sample_info.e_type.lower()
    else:
        raise Exception(f"Unexpected e_type found: {sample_info.e_type}")

    return sample_info


def start_hardcore_analysis(sample, context):
    """
    This function parses the submitted ELF sample and kicks off
    static/dynamic analysis.

    :param sample: Submitted sample's metadata object
    :type sample: web.models.SampleMetadata
    :param context: A dictionary containing username, user-submitted form
                    parameters and other analysis options/metadata.
    :type context: dict
    :return: None
    :rtype: None
    """
    LOG.debug("Creating TaskMetadata object and starting hardcore analysis")
    # There should be no exception raised when creating a task object.
    # If there is an exception, it's a bug.
    submission_id = os.path.basename(os.path.normpath(context["dirpath"]))
    taskreports = TaskReports.objects.create(status=TaskStatus.IN_PROGRESS)
    exec_args = context["execution_arguments"][:TaskMetadata._meta.get_field("cmdline").max_length]
    task = TaskMetadata.objects.create(
        uuid=submission_id,
        sha256=sample,
        errors=False,
        status=TaskStatus.IN_PROGRESS,
        cmdline=exec_args,
        userland_tracing=context["userland_tracing"],
        taskreports=taskreports
    )

    # Among other things, the config file specifies which analysis modules to
    # apply on the sample.
    config_fpath = os.path.join(settings.BASE_DIR, "analysis", "config.json")
    with open(config_fpath, "r") as f:
        config = json.load(f)
    context["config"] = config

    sample_path = os.path.join(context["dirpath"], context["file_hashes"]["sha256"])
    # Set TLSH hash for sample
    sample.tlsh = tlsh.hash(open(sample_path, "rb").read())
    sample.save(update_fields=["tlsh"])

    context["sample_path"] = sample_path
    # If any corruption/anti-analysis techniques in the sample are found,
    # then fixed_sample_path will not be equal to sample_path. Otherwise,
    # they are equal.
    basic_info, sample_path_, _ = parse_elf.get_basic_info(sample_path)
    if sample_path_.endswith("_fixed"):
        # Sample was fixed
        context["fixed_sample_path"] = sample_path_

    if basic_info is None:
        LOG.error("Could not parse ELF binary")
        task.error_msg = "Could not parse ELF binary"
        task.errors = True
        task.status = TaskStatus.ERROR
        task.end_time = datetime.datetime.now()
        task.save(update_fields=["error_msg", "errors", "status", "end_time"])
        return

    if basic_info.err_msg:
        LOG.error(f"Error while parsing ELF binary: {basic_info.err_msg}")
        task.error_msg = basic_info.err_msg
        task.errors = True
        task.save(update_fields=["error_msg", "errors"])

    # Have to align certain fields as required by SampleMetadata model.
    basic_info = _align_as_per_model(basic_info)
    sample.bintype = basic_info.e_type
    sample.save(update_fields=["bintype"])

    # Run configured analysis modules asynchronously
    analysis_modules = config.get("analysis", [])
    taskreports.status = TaskStatus.IN_PROGRESS
    taskreports.save(update_fields=["status"])
    for module in analysis_modules:
        LOG.debug(f"Starting analysis module: {module}")
        mod = importlib.import_module(f"analysis.analysis.{module}")
        mod.start_analysis.delay(context)

    # TODO: Detection subsystem
    check_detection.delay(context)
