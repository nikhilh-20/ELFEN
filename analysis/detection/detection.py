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
import time
import yara
import logging
import datetime

from celery import shared_task
from django.conf import settings

from web.models import SampleMetadata
from analysis.models import Detection, TaskMetadata
from analysis.enum import TaskStatus
from analysis.detection.static import check_static_analysis
from analysis.detection.dynamic import check_dynamic_analysis, extract_store_c2

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def _get_yara_rules():
    """
    Gets all YARA rules (.yar, .yara extensions) from yara rules directory and
    compiles them.

    :return: Compiled YARA rules
    :rtype: yara.Rules
    """
    yara_rules_dir = os.path.join(settings.BASE_DIR, "rsrc", "detection", "yara_rules")

    yara_fpaths = {}
    for f in os.listdir(yara_rules_dir):
        if f.endswith(".yar") or f.endswith(".yara"):
            # Namespace == filename without extension
            namespace = os.path.splitext(f)[0]
            yara_fpath = os.path.join(yara_rules_dir, f)
            yara_fpaths.update({namespace: yara_fpath})

    compiled_rules = yara.compile(filepaths=yara_fpaths, includes=False)
    return compiled_rules


@shared_task(queue="detection_analysis")
def check_detection(context):
    """
    Analyzes static and dynamic reports to generate a score for the task.
    Detection is analyzed only if reports for all analysis modules (static, dynamic, etc.)
    are available.

    :param context: Context around the submitted sample, including the directory
                    in which the file exists, its hash, names of any additional
                    files submitted, dynamic analysis execution time, execution
                    cmdline arguments.
    :type context: dict
    :return: None
    :rtype: None
    """
    LOG.debug(f"Detection analysis waiting for analysis modules to complete.")

    sha256 = context["file_hashes"]["sha256"]
    dirpath = context["dirpath"]
    execution_time = int(context["execution_time"])
    submission_uuid = context["submission_uuid"]
    parent_task = TaskMetadata.objects.get(uuid=submission_uuid)
    taskreports = parent_task.taskreports

    data = {
        "username": context["username"],
        "dirpath": dirpath,
        "submission_uuid": submission_uuid,
        "dynamic_analysis_dir": os.path.join(dirpath, "dynamic_analysis"),
        "file_hashes": context["file_hashes"],
        "sample_path": context["sample_path"],
        "additional_files": context["additional_files"]
    }
    malware_families = []

    analysis_modules = context.get("config", {}).get("analysis", [])
    if not analysis_modules:
        LOG.error("No analysis module defined. No detection analysis will be performed.")
        return
    LOG.debug(f"Detection to be applied on reports for {analysis_modules} analyses")

    data["compiled_yara_rules"] = _get_yara_rules()

    for i, module in enumerate(analysis_modules):
        while getattr(taskreports, f"{module}_reports") is None:
            # Wait for report object to be created for each analysis module
            # Should be quick
            time.sleep(1)
            taskreports.refresh_from_db()

    LOG.debug(f"Starting detection analysis for {submission_uuid}")
    detection = Detection.objects.create()
    all_scores = []

    if "static" in analysis_modules:
        LOG.debug(f"Applying detection on static analysis report")

        static_score, static_detectors, malware_families_static, err_msg =\
            check_static_analysis(taskreports.static_reports, execution_time,
                                  data)

        if static_score is None:
            # Something went wrong with static analysis
            detection.status = TaskStatus.ERROR
            detection.errors = True
            detection.error_msg = err_msg
            detection.save(update_fields=["status", "errors", "error_msg"])

        malware_families.extend(malware_families_static)
        all_scores.append(static_score)
    else:
        static_score, static_detectors = None, []

    detection.static_analysis_score = static_score
    detection.static_analysis_detectors = [detector["detector"] for detector in static_detectors]
    detection.save(update_fields=["static_analysis_score", "static_analysis_detectors"])

    if "dynamic" in analysis_modules:
        LOG.debug(f"Applying detection on dynamic analysis report")

        dynamic_score, dynamic_detectors, malware_families_dynamic, err_msg = \
            check_dynamic_analysis(taskreports.dynamic_reports, execution_time,
                                   data)
        if dynamic_score is None:
            # Something went wrong with dynamic analysis
            detection.status = TaskStatus.ERROR
            detection.errors = True
            detection.error_msg = err_msg
            detection.save(update_fields=["status", "errors", "error_msg"])

        malware_families.extend(malware_families_dynamic)
        all_scores.append(dynamic_score)

        # Maybe move this to the analysis pipeline
        LOG.debug("Extracting C2 IP/port from network behavior, if any")
        extract_store_c2(parent_task)
    else:
        dynamic_score, dynamic_detectors = None, []

    detection.dynamic_analysis_score = dynamic_score
    detection.dynamic_analysis_detectors = [detector["detector"] for detector in dynamic_detectors]
    detection.score = max(all_scores) if all_scores else 0
    detection.status = TaskStatus.COMPLETE
    detection.save(update_fields=["dynamic_analysis_score", "dynamic_analysis_detectors",
                                  "score", "status"])

    taskreports.status = TaskStatus.COMPLETE
    taskreports.save(update_fields=["status"])

    # Update SampleMetadata to keep track of all families associated with the given sample
    # Any FPs in ELFEN will have an effect here - FP family will be associated with a sample
    sample = SampleMetadata.objects.get(sha256=sha256)
    existing_families = sample.family
    if existing_families:
        existing_families.extend(malware_families)
        existing_families = list(set(existing_families))
    else:
        existing_families = list(set(malware_families))
    sample.family = existing_families
    sample.save(update_fields=["family"])

    # Only malware families detected by the given task should be showed on the task
    # overview page.
    parent_task.refresh_from_db()
    parent_task.family = list(set(malware_families))
    parent_task.detection = detection
    parent_task.end_time = datetime.datetime.now()
    if parent_task.taskreports.errors:
        parent_task.status = TaskStatus.ERROR
        parent_task.errors = True
        parent_task.error_msg = parent_task.taskreports.error_msg
        parent_task.save(update_fields=["detection", "end_time", "status", "family",
                                        "errors", "error_msg"])
    else:
        parent_task.status = TaskStatus.COMPLETE
        parent_task.save(update_fields=["detection", "end_time", "status", "family"])
