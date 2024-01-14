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
import time
import logging
import datetime
import importlib

from analysis.enum import TaskStatus
from analysis.analysis_models.dynamic_analysis import ConnectEvent
from analysis.models import Configuration

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)

DETECTORS = [
    "ransomware", "process", "mem_yara", "mutex", "file_ops"
]


def launch_detectors(dynamic_reports, data):
    """
    Launches all dynamic analysis detectors on the given dynamic analysis report.

    :param dynamic_reports: DynamicAnalysisReports object
    :type dynamic_reports: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    :param data: Max score, triggered detectors, identified malware families,
                 error message, if any
    :type data: int, list, list, str
    """
    objs = []

    for s in DETECTORS:
        module = importlib.import_module(f"analysis.detection.detectors.{s}")
        class_name = s.replace("_", " ").title().replace(" ", "")
        class_ = getattr(module, class_name)
        obj = class_(dynamic_reports)
        obj.detect(data)
        objs.append(obj)

    err_msg = ", ".join([s.err_msg for s in objs if s.err_msg])
    score = max([s.score for s in objs], default=0)

    malware_families = []
    triggered_detectors = []
    for s in objs:
        if s.triggered_detectors:
            triggered_detectors.extend(s.triggered_detectors)
        families = getattr(s, "family", [])
        if families:
            malware_families.extend(families)

    return score, triggered_detectors, list(set(malware_families)), err_msg


def check_dynamic_analysis(dynamic_reports, data):
    """
    Examines dynamic analysis reports to generate a score for the task

    :param dynamic_reports: DynamicAnalysisReports object
    :type dynamic_reports: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    :param data: Analysis metadata such as submission UUID, compiled set of YARA
                 rules, dynamic analysis directory, etc.
    :type data: dict
    :return: Max score, triggered detectors, identified malware families,
                 error message, if any
    :rtype: int|None, list, list, str
    """
    score, tags, detectors = 0, [], []
    err_msg, execution_time = "", data["execution_time"]
    if dynamic_reports.status == TaskStatus.ERROR:
        return score, detectors, tags, err_msg

    time_delta = 300
    LOG.debug(f"Waiting for dynamic analysis report to complete")
    start_time = datetime.datetime.now()
    while dynamic_reports.status != TaskStatus.COMPLETE:
        time.sleep(10)
        dynamic_reports.refresh_from_db()
        if dynamic_reports.status == TaskStatus.ERROR:
            err_msg = "Dynamic analysis failed. No detection analysis from it."
            LOG.error(err_msg)
            return score, detectors, tags, err_msg
        if (datetime.datetime.now() - start_time).seconds > (execution_time + time_delta):
            err_msg = f"Dynamic analysis took too long to complete: >{execution_time + time_delta}s"
            LOG.error(err_msg)
            return None, detectors, tags, err_msg

    return launch_detectors(dynamic_reports, data)


def extract_store_c2(parent_task):
    """
    Extract C2 information from the network behavior

    :param parent_task: Given task metadata object
    :type parent_task: analysis.models.TaskMetadata
    :return: None
    :rtype: None
    """
    c2 = set()
    config_objs = []

    try:
        sha256 = parent_task.sha256
    except AttributeError:
        LOG.error(f"No sha256 found for task UUID: {parent_task.uuid}")
        return

    try:
        kernel_trace_id = parent_task.taskreports.dynamic_reports.kernel_trace
    except AttributeError:
        LOG.error(f"No kernel trace found for task UUID: {parent_task.uuid}")
        return

    objs = ConnectEvent.objects.filter(kernel_trace=kernel_trace_id)

    for obj in objs:
        c2_ip = obj.ip
        # Filter out Google DNS (8.8.8.8, 8.8.4.4), localhost (127.0.0.1),
        # broadcast (255.255.255.255), self-assigned (0.0.0.0)
        # These aren't considered to be part of C2 configuration
        if c2_ip in ("8.8.8.8", "8.8.4.4", "127.0.0.1", "255.255.255.255", "0.0.0.0"):
            continue

        c2_port = obj.port
        if c2_ip:
            c2.add(f"{c2_ip}:{c2_port}")

    for c in c2:
        c2_ip, c2_port = c.split(":")
        config_objs.append(Configuration(sha256=sha256, parent_task=parent_task,
                                         ip=c2_ip, port=c2_port))

    if config_objs:
        Configuration.objects.bulk_create(config_objs)
