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

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)

DETECTORS = []


def launch_detectors(network_reports, data):
    """
    Launches all network analysis detectors on the given network analysis report.

    :param network_reports: NetworkAnalysisReports object
    :type network_reports: analysis.analysis_models.network_analysis.NetworkAnalysisReports
    :param data: Max score, triggered detectors, identified malware families,
                 error message, if any
    :type data: int, list, list, str
    """
    objs = []

    for s in DETECTORS:
        module = importlib.import_module(f"analysis.detection.detectors.{s}")
        class_name = s.replace("_", " ").title().replace(" ", "")
        class_ = getattr(module, class_name)
        obj = class_(network_reports)
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


def check_network_analysis(network_reports, data):
    """
    Examines network analysis reports to generate a score for the task

    :param network_reports: NetworkAnalysisReports object
    :type network_reports: analysis.analysis_models.network_analysis.NetworkAnalysisReports
    :param data: Analysis metadata such as submission UUID, compiled set of YARA
                 rules, dynamic analysis directory, etc.
    :type data: dict
    :return: Max score, triggered detectors, identified malware families,
                 error message, if any
    :rtype: int|None, list, list, str
    """
    score, tags, detectors = 0, [], []
    err_msg, execution_time = "", data["execution_time"]
    if network_reports.status == TaskStatus.ERROR:
        return score, detectors, tags, err_msg

    time_delta = 300
    LOG.debug(f"Waiting for network analysis report to complete")
    start_time = datetime.datetime.now()
    while network_reports.status != TaskStatus.COMPLETE:
        time.sleep(10)
        network_reports.refresh_from_db()
        if network_reports.status == TaskStatus.ERROR:
            err_msg = "Network analysis failed. No detection analysis from it."
            LOG.error(err_msg)
            return score, detectors, tags, err_msg
        elif network_reports.status == TaskStatus.NOT_STARTED:
            # By the time control reaches here, network analysis DB object
            # should have been set to IN_PROGRESS, if applicable.
            LOG.warning("Network analysis not started")
            return score, detectors, tags, "Network analysis not started"

        if (datetime.datetime.now() - start_time).seconds > (execution_time + time_delta):
            err_msg = f"Network analysis took too long to complete: >{execution_time + time_delta}s"
            LOG.error(err_msg)
            return None, detectors, tags, err_msg

    return launch_detectors(network_reports, data)
