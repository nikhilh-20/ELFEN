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
import json
import logging
import datetime

from celery import shared_task
from django.conf import settings

from web.models import SampleMetadata
from analysis.models import Detection, TaskMetadata
from analysis.enum import TaskStatus
from analysis.detection.static import check_static_analysis
from analysis.detection.dynamic import check_dynamic_analysis, extract_store_c2
from analysis.detection.network import check_network_analysis

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


def _get_malicious_file_extensions():
    """
    Gets all known malicious file extensions from malicious_file_extensions.json

    :return: Malicious file extensions mapping
    :rtype: dict
    """
    mal_ext_fpath = os.path.join(settings.BASE_DIR, "rsrc", "detection",
                                 "malicious_file_extensions.json")

    with open(mal_ext_fpath, "r") as f:
        return json.load(f)


def check_static_detection(data, taskreports, detection):
    """
    This function performs detection analysis on the static analysis report.

    :param data: Analysis metadata such as submission UUID, compiled set of YARA
                 rules, dynamic analysis directory, etc.
    :type data: dict
    :param taskreports: TaskReports object
    :type taskreports: analysis.models.TaskReports
    :param detection: Detection object
    :type detection: analysis.models.Detection
    :return: Static analysis score, malware families detected, error message, if any
    :rtype: int, list, list, str
    """
    LOG.debug(f"Applying detection on static analysis report")

    static_score, static_detectors, malware_families_static, err_msg = \
        check_static_analysis(taskreports.static_reports, data)

    if static_score is None:
        # Something went wrong with static analysis
        detection.status = TaskStatus.ERROR
        detection.errors = True
        detection.error_msg += err_msg
        detection.save(update_fields=["status", "errors", "error_msg"])
        return 0, [], [], err_msg

    detection.static_analysis_score = static_score
    detection.static_analysis_detectors = [detector["detector"]
                                           for detector in static_detectors]
    detection.save(update_fields=["static_analysis_score", "static_analysis_detectors"])

    mitre_attack = []
    for detector in static_detectors:
        mitre_ = [m_.strip() for m_ in detector.get("detector", {}).get("mitre_attack", []).split(",")]
        mitre_attack.extend(mitre_)
    mitre_attack = list(set(mitre_attack))

    LOG.debug(f"Finished applying detection on static analysis report")
    return static_score, mitre_attack, malware_families_static, ""


def check_dynamic_detection(data, taskreports, detection):
    """
    This function performs detection analysis on the dynamic analysis report.

    :param data: Analysis metadata such as submission UUID, compiled set of YARA
                 rules, dynamic analysis directory, etc.
    :type data: dict
    :param taskreports: TaskReports object
    :type taskreports: analysis.models.TaskReports
    :param detection: Detection object
    :type detection: analysis.models.Detection
    :return: Dynamic analysis score, malware families detected, error message, if any
    :rtype: int, list, str
    """
    LOG.debug(f"Applying detection on dynamic analysis report")

    dynamic_score, dynamic_detectors, malware_families_dynamic, err_msg = \
        check_dynamic_analysis(taskreports.dynamic_reports, data)

    if dynamic_score is None:
        # Something went wrong with dynamic analysis
        detection.status = TaskStatus.ERROR
        detection.errors = True
        detection.error_msg += err_msg
        detection.save(update_fields=["status", "errors", "error_msg"])
        return 0, [], [], err_msg

    detection.dynamic_analysis_score = dynamic_score
    detection.dynamic_analysis_detectors = [detector["detector"]
                                            for detector in dynamic_detectors]
    detection.save(update_fields=["dynamic_analysis_score", "dynamic_analysis_detectors"])

    mitre_attack = []
    for detector in dynamic_detectors:
        mitre_ = [m_.strip() for m_ in detector.get("detector", {}).get("mitre_attack", []).split(",")]
        mitre_attack.extend(mitre_)
    mitre_attack = list(set(mitre_attack))

    LOG.debug(f"Finished applying detection on dynamic analysis report")
    return dynamic_score, mitre_attack, malware_families_dynamic, ""


def check_network_detection(data, taskreports, detection):
    """
    This function performs detection analysis on the network analysis report.

    :param data: Analysis metadata such as submission UUID, compiled set of YARA
                 rules, dynamic analysis directory, etc.
    :type data: dict
    :param taskreports: TaskReports object
    :type taskreports: analysis.models.TaskReports
    :param detection: Detection object
    :type detection: analysis.models.Detection
    :return: Static analysis score, malware families detected, error message, if any
    :rtype: int, list, list, str
    """
    LOG.debug(f"Applying detection on network analysis report")

    network_score, network_detectors, malware_families_network, err_msg = \
        check_network_analysis(taskreports.network_reports, data)

    if network_score is None:
        # Something went wrong with network analysis
        detection.status = TaskStatus.ERROR
        detection.errors = True
        detection.error_msg += err_msg
        detection.save(update_fields=["status", "errors", "error_msg"])
        return 0, [], [], err_msg

    detection.network_analysis_score = network_score
    detection.network_analysis_detectors = [detector["detector"]
                                            for detector in network_detectors]
    detection.save(update_fields=["network_analysis_score", "network_analysis_detectors"])

    mitre_attack = []
    for detector in network_detectors:
        mitre_ = [m_.strip() for m_ in detector.get("detector", {}).get("mitre_attack", []).split(",")]
        mitre_attack.extend(mitre_)
    mitre_attack = list(set(mitre_attack))

    LOG.debug(f"Finished applying detection on network analysis report")
    return network_score, mitre_attack, malware_families_network, ""


def update_sample_malware_families(sample, malware_families):
    """
    This function updates the malware families associated with the given sample in the DB.
    Any FPs in ELFEN will have an effect here - FP family will be associated with a sample

    :param sample: SampleMetadata object
    :type sample: web.models.SampleMetadata
    :param malware_families: Malware families associated with the sample as
                             detected in this task
    :type malware_families: list
    :return: None
    """
    LOG.debug("Updating malware families associated with the given sample in the DB")

    existing_families = list(sample.family)
    if existing_families:
        existing_families.extend(malware_families)
        existing_families = list(set(existing_families))
    else:
        existing_families = list(set(malware_families))
    sample.family = existing_families
    sample.save(update_fields=["family"])

    LOG.debug("Updated malware families associated with the given sample in the DB")


def update_parent_task(parent_task, malware_families, detection):
    """
    This function updates the parent task object. It updates the end time of
    the task, associated detection object and malware families

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param malware_families: Malware families detected during given analysis
    :type malware_families: list
    :param detection: Detection object
    :type detection: analysis.models.Detection
    :return: None
    """
    LOG.debug("Updating parent task")

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

    LOG.debug("Updated parent task")


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
        "additional_files": context["additional_files"],
        "execution_time": int(context["execution_time"]),
        "compiled_yara_rules": _get_yara_rules(),
        "malicious_file_extensions": _get_malicious_file_extensions(),
    }
    malware_families, mitre_attack = [], []

    analysis_modules = context.get("config", {}).get("analysis", [])
    if not analysis_modules:
        LOG.error("No analysis module defined. No detection analysis will be performed.")
        return
    LOG.debug(f"Detection to be applied on reports for {analysis_modules} analyses")

    for i, module in enumerate(analysis_modules):
        while getattr(taskreports, f"{module}_reports") is None:
            # Wait for report object to be created for each analysis module
            # Should be quick
            time.sleep(1)
            taskreports.refresh_from_db()

    LOG.debug(f"Starting detection analysis for {submission_uuid}")
    detection = Detection.objects.create()
    all_scores, detection_error = [], False

    if "static" in analysis_modules:
        static_score, mitre_attack_static, malware_families_static, err_msg = \
            check_static_detection(data, taskreports, detection)
        if err_msg:
            detection_error = True
    else:
        static_score, mitre_attack_static, malware_families_static = 0, [], []

    mitre_attack.extend(mitre_attack_static)
    malware_families.extend(malware_families_static)
    all_scores.append(static_score)

    if "dynamic" in analysis_modules:
        dynamic_score, mitre_attack_dynamic, malware_families_dynamic, err_msg = \
            check_dynamic_detection(data, taskreports, detection)
        if err_msg:
            detection_error = True

        # Maybe move this to the analysis pipeline
        LOG.debug("Extracting C2 IP/port from network behavior, if any")
        extract_store_c2(parent_task)
    else:
        dynamic_score, mitre_attack_dynamic, malware_families_dynamic = 0, [], []

    mitre_attack.extend(mitre_attack_dynamic)
    malware_families.extend(malware_families_dynamic)
    all_scores.append(dynamic_score)

    if "network" in analysis_modules:
        network_score, mitre_attack_network, malware_families_network, err_msg = \
            check_network_detection(data, taskreports, detection)
        if err_msg:
            detection_error = True
    else:
        network_score, mitre_attack_network, malware_families_network = 0, [], []

    mitre_attack.extend(mitre_attack_network)
    detection.mitre_attack = list(set(mitre_attack))
    malware_families.extend(malware_families_network)
    all_scores.append(network_score)

    # Calculate final detection score
    detection.score = max(all_scores) if all_scores else 0

    # If there was any detection analysis error, it would already have been
    # updated in the DB
    if not detection_error:
        detection.status = TaskStatus.COMPLETE
        detection.save(update_fields=["score", "status", "mitre_attack"])

    taskreports.status = TaskStatus.COMPLETE
    taskreports.save(update_fields=["status"])

    # Update SampleMetadata to keep track of all families associated with the given sample
    update_sample_malware_families(SampleMetadata.objects.get(sha256=sha256),
                                   malware_families)

    # Close up shop
    update_parent_task(parent_task, malware_families, detection)
