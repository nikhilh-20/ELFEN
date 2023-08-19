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
from django.conf import settings
from analysis.reporting.static import get_static_backend_report
from analysis.reporting.dynamic import get_dynamic_backend_report
from analysis.reporting.detection import get_detection_backend_report
from analysis.enum import status_mapping
from analysis.reporting.enum import StaticBackends, DynamicBackends, DetectionBackends
from analysis.analysis_models.static_analysis import *
from analysis.analysis_models.dynamic_analysis import DynamicAnalysisReports, DynamicAnalysisMetadata
from analysis.models import TaskMetadata, TaskReports, Detection


logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def download_artifact(submission_uuid, backend):
    """
    This function finds the given file artifact and returns a handle to it.

    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param backend: Backend name
    :type backend: str
    :return: Handle to artifact file or None
    :rtype: _io.BufferedReader or None
    """
    if backend == "droppedfiles":
        dropped_file_zip = os.path.join(settings.BASE_DIR, "media", "web",
                                        submission_uuid, "dynamic_analysis", "dropped.zip")
        if os.path.isfile(dropped_file_zip):
            return open(dropped_file_zip, "rb")
    elif backend == "strings":
        strings_file_json = os.path.join(settings.BASE_DIR, "media", "web",
                                         submission_uuid, "strings.json")
        if os.path.isfile(strings_file_json):
            return open(strings_file_json, "rb")
    elif backend == "memstrings":
        memstrings_file_json = os.path.join(settings.BASE_DIR, "media", "web",
                                            submission_uuid, "dynamic_analysis", "memstrings.json")
        if os.path.isfile(memstrings_file_json):
            return open(memstrings_file_json, "rb")

    return None


def get_backend_report(submission_uuid, backend):
    """
    This function retrieves report for a specific backend in the static or
    dynamic analysis pipeline.

    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param backend: Backend name
    :type backend: str
    :return: Analysis report for given backend for given submission
             UUID or None
    :rtype: dict or None
    """
    try:
        backend = getattr(StaticBackends, backend.upper())
        return get_static_backend_report(submission_uuid, backend)
    except AttributeError:
        pass

    try:
        backend = getattr(DynamicBackends, backend.upper())
        return get_dynamic_backend_report(submission_uuid, backend)
    except AttributeError:
        pass

    try:
        backend = getattr(DetectionBackends, backend.upper())
        return get_detection_backend_report(submission_uuid, backend)
    except AttributeError:
        pass

    LOG.error(f"Error during getting backend report: {backend}. No such backend found")


def _get_arch_endian_bitness(static_analysis_reports, reports):
    """
    This function updates the report with basic sample metadata.

    :param static_analysis_reports: Static analysis reports
    :type static_analysis_reports: analysis.analysis_models.static_analysis.StaticAnalysisReports
    :param reports: Dictionary of reports
    :type reports: dict
    :return: Updated report
    :rtype: dict
    """
    try:
        reports["sample_metadata"]["arch"] = static_analysis_reports.samplefeatures.arch
        if static_analysis_reports.samplefeatures.endian == "LE":
            reports["sample_metadata"]["endian"] = "Little"
        else:
            reports["sample_metadata"]["endian"] = "Big"
        if static_analysis_reports.samplefeatures.bit:
            sample_bitness = static_analysis_reports.samplefeatures.bit.split("_")[1]
        else:
            sample_bitness = None
        reports["sample_metadata"]["bitness"] = sample_bitness
    except AttributeError:
        # Static analysis is not yet complete
        reports["sample_metadata"]["arch"] = None
        reports["sample_metadata"]["endian"] = None
        reports["sample_metadata"]["bitness"] = None

    return reports


def get_static_reports(static_analysis_reports, reports, submission_uuid):
    """
    Get analysis reports for all configured static analysis backends.

    :param static_analysis_reports: Static analysis reports object
    :type static_analysis_reports: analysis.analysis_models.static_analysis.StaticAnalysisReports
    :param reports: Dictionary of reports
    :type reports: dict
    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :return: Updated report
    :rtype: dict
    """
    if not static_analysis_reports:
        return reports

    try:
        static_analysis_reports.samplefeatures
    except SampleFeatures.DoesNotExist:
        return reports

    # If static analysis report exists, populate metadata about the sample
    reports = _get_arch_endian_bitness(static_analysis_reports, reports)

    for attr in dir(StaticBackends):
        if (not callable(getattr(StaticBackends, attr)) and
                not attr.startswith("__")):
            backend = getattr(StaticBackends, attr)
            backend_status, backend_status_desc = _get_backend_status(static_analysis_reports, backend)

            reports["data"]["static"][backend] = {
                "status": backend_status_desc,
                "data": None,
                "errors": None,
                "error_msg": []
            }

            if backend_status == TaskStatus.IN_PROGRESS:
                continue

            backend_report = get_backend_report(submission_uuid, backend)
            error_msg = backend_report["error_msg"]
            if backend_status is None and backend_status_desc is None:
                backend_status = TaskStatus.ERROR if error_msg else TaskStatus.NOT_STARTED
                backend_status_desc = status_mapping[backend_status]

            reports["data"]["static"][backend]["errors"] = backend_report["errors"]
            reports["data"]["static"][backend]["error_msg"] = error_msg
            reports["data"]["static"][backend]["data"] = backend_report["data"]
            reports["data"]["static"][backend]["status"] = backend_status_desc

    return reports


def get_dynamic_reports(dynamic_analysis_reports, reports, submission_uuid, web):
    """
    Get analysis reports for all configured dynamic analysis backends.

    :param dynamic_analysis_reports: Dynamic analysis reports object
    :type dynamic_analysis_reports: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    :param reports: Dictionary of reports
    :type reports: dict
    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param web: Flag to indicate if this is a web request
    :type web: bool
    :return: Updated report
    :rtype: dict
    """
    if not dynamic_analysis_reports:
        return reports

    try:
        reports["console_output"] = dynamic_analysis_reports.metadata.console_output.tobytes()
    except (DynamicAnalysisMetadata.DoesNotExist, AttributeError):
        # Dynamic analysis is not complete yet
        reports["console_output"] = None
        pass

    for attr in dir(DynamicBackends):
        if (not callable(getattr(DynamicBackends, attr)) and
                not attr.startswith("__")):
            backend = getattr(DynamicBackends, attr)

            # There's no need to check for status of each backend. All dynamic
            # analysis backends will be complete when dynamic analysis completes.
            backend_status, backend_status_desc = (dynamic_analysis_reports.status,
                                                   status_mapping[dynamic_analysis_reports.status])

            reports["data"]["dynamic"][backend] = {
                "status": backend_status_desc,
                "data": None,
                "errors": None,
                "error_msg": []
            }

            if backend_status == TaskStatus.IN_PROGRESS:
                continue

            # Retrieve full report only for API requests. This is to make task overview page
            # web requests faster and not timeout. Dynamic analysis reports can be large.
            # Except dropped files, c2 config. That should be a relatively small list.
            if not web or backend in ("droppedfiles", "c2config"):
                backend_report = get_backend_report(submission_uuid, backend)
            else:
                backend_report = {"errors": False, "error_msg": [], "data": []}
            error_msg = backend_report["error_msg"]
            if backend_status is None and backend_status_desc is None:
                backend_status = TaskStatus.ERROR if error_msg else TaskStatus.NOT_STARTED
                backend_status_desc = status_mapping[backend_status]

            reports["data"]["dynamic"][backend]["errors"] = backend_report["errors"]
            reports["data"]["dynamic"][backend]["error_msg"] = error_msg
            reports["data"]["dynamic"][backend]["data"] = backend_report["data"]
            reports["data"]["dynamic"][backend]["status"] = backend_status_desc

    return reports


def get_detection_reports(detection, reports, submission_uuid):
    """
    Get analysis reports for all configured detection analysis backends.

    :param detection: Detection analysis report model
    :type detection: analysis.models.Detection
    :param reports: Dictionary of reports
    :type reports: dict
    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :return: Updated report
    :rtype: dict
    """
    try:
        reports["task_score"] = detection.score
    except AttributeError:
        reports["task_score"] = None

    try:
        sample = TaskMetadata.objects.get(uuid=submission_uuid).sha256
        reports["data"]["detection"] = {"classification": {"tags": ",".join(sample.tags)}}
    except AttributeError:
        reports["data"]["detection"] = {"classification": {"tags": None}}

    for attr in dir(DetectionBackends):
        if (not callable(getattr(DetectionBackends, attr)) and
                not attr.startswith("__")):
            backend = getattr(DetectionBackends, attr)

            # There's no need to check for status of each backend. All detection
            # analysis backends will be complete when detection analysis completes.
            try:
                backend_status, backend_status_desc = (detection.status,
                                                       status_mapping[detection.status])
            except AttributeError:
                backend_status, backend_status_desc = TaskStatus.NOT_STARTED, status_mapping[TaskStatus.NOT_STARTED]

            reports["data"]["detection"][backend] = {
                "status": backend_status_desc,
                "data": None,
                "errors": None,
                "error_msg": []
            }

            if backend_status == TaskStatus.IN_PROGRESS:
                continue

            backend_report = get_backend_report(submission_uuid, backend)
            error_msg = backend_report["error_msg"]
            if backend_status is None and backend_status_desc is None:
                backend_status = TaskStatus.ERROR if error_msg else TaskStatus.NOT_STARTED
                backend_status_desc = status_mapping[backend_status]

            reports["data"]["detection"][backend]["errors"] = backend_report["errors"]
            reports["data"]["detection"][backend]["error_msg"] = error_msg
            reports["data"]["detection"][backend]["data"] = backend_report["data"]
            reports["data"]["detection"][backend]["status"] = backend_status_desc

    return reports


def _get_backend_status(model, backend):
    """
    Check the task status of the given backend.

    :param model: Static analysis reports or dynamic analysis reports model
    :type model: analysis.analysis_models.static_analysis.StaticAnalysisReports or
                 analysis.analysis_models.static_analysis.DynamicAnalysisReports
    :param backend: Backend name
    :type backend: str
    :return: Task status and description
    :rtype: tuple
    """
    try:
        status = getattr(model, backend).status
        status_desc = status_mapping[getattr(model, backend).status]
        return status, status_desc
    except AttributeError:
        return None, None


def get_all_reports(submission_uuid, web=False):
    """
    Get all reports for the given submission UUID for the task overview page.
    For the overview page, dynamic analysis reports are not retrieved to lower
    processing time.

    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param web: Whether this is a web request
    :type web: bool
    :return: Analysis report for given submission/task UUID
    :rtype: dict or None
    """
    reports = {
        "error_msg": "",
        "task_status": status_mapping[TaskStatus.NOT_STARTED],
        "submission_uuid": submission_uuid,
    }

    # Check if the task exists
    try:
        parent_task = TaskMetadata.objects.get(uuid=submission_uuid)
    except TaskMetadata.DoesNotExist:
        # Either the task hasn't started yet, or there is no such task
        return None

    # Check if this task is the most recent task for the associated sample
    all_tasks = TaskMetadata.objects.filter(sha256=parent_task.sha256)
    if parent_task != all_tasks.latest("start_time"):
        # This task is not the most recent task for the associated sample
        reports["warning"] = "Information may not be the latest. Most recent task UUID for sample: " \
                             f"{all_tasks.latest('start_time').uuid}" \

    reports.update({
        "task_status": status_mapping[parent_task.status],
        "error_msg": parent_task.error_msg,
        "task_start_time": parent_task.start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "task_cmdline": parent_task.cmdline,
        "sample_metadata": {
            "md5": parent_task.sha256.md5,
            "sha1": parent_task.sha256.sha1,
            "sha256": parent_task.sha256.sha256
        },
        "family": parent_task.family,
        "data": {
            "static": {},
            "dynamic": {},
            "detection": {}
        }
    })
    if parent_task.status == TaskStatus.COMPLETE or parent_task.status == TaskStatus.ERROR:
        reports["task_end_time"] = parent_task.end_time.strftime("%Y-%m-%d %H:%M:%S")

    # Check if static and dynamic analysis reports exist
    try:
        task_reports = parent_task.taskreports
        static_analysis_reports = task_reports.static_reports
        dynamic_analysis_reports = task_reports.dynamic_reports
        detection = parent_task.detection
    except (TaskReports.DoesNotExist, StaticAnalysisReports.DoesNotExist,
            DynamicAnalysisReports.DoesNotExist, Detection.DoesNotExist):
        return reports

    if static_analysis_reports:
        # Populate static analysis reports info
        reports = get_static_reports(static_analysis_reports, reports,
                                     submission_uuid)

    if dynamic_analysis_reports:
        # Populate dynamic analysis reports info
        reports = get_dynamic_reports(dynamic_analysis_reports, reports,
                                      submission_uuid, web)

    # Populate detection reports info
    reports = get_detection_reports(detection, reports, submission_uuid)

    return reports
