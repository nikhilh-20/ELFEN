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

from analysis.models import TaskMetadata, Configuration
from analysis.analysis_models.dynamic_analysis import MemoryStrings
from analysis.reporting.utils.get_dynamic_reports_values import *


def get_fileops_report(parent_task):
    """
    This function retrieves all filesystem-related operations associated with the
    given task.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: File operations report and error message
    :rtype: tuple
    """
    return get_fileops_values(parent_task)


def get_procops_report(parent_task):
    """
    This function retrieves all process-related operations associated with the
    given task.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Process operations report and error message
    :rtype: tuple
    """
    return get_procops_values(parent_task)


def get_netops_report(parent_task):
    """
    This function retrieves all network-related operations associated with the
    given task.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Network operations report and error message
    :rtype: tuple
    """
    return get_netops_values(parent_task)


def get_userland_report(parent_task):
    """
    This function retrieves all userland operations for the given task

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Userland related operations and error message
    :rtype: tuple
    """
    return get_userland_values(parent_task)


def get_droppedfiles_report(parent_task):
    """
    This function retrieves names of all dropped files associated
    with the given task. These will also be available for download to the user
    in the form of an encrypted (pass: infected) zip.

    [
        "dropped_filename1",
        "dropped_filename2",
        ...
    ]

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Dropped file names and error message
    :rtype: tuple
    """
    data = set()
    error_msg = []
    dropped_files = parent_task.taskreports.dynamic_reports.dropped_files

    if dropped_files:
        for fname in dropped_files:
            data.add(fname)

    return list(data), error_msg


def get_memstrings_report(parent_task):
    """
    This function retrieves the memory strings associated with the given task.

    ["str1", "str2", ...]

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Memory strings and error message
    :rtype: tuple
    """
    error_msg = []

    try:
        obj = parent_task.taskreports.dynamic_reports.memstrings
    except (AttributeError, MemoryStrings.DoesNotExist) as err:
        error_msg = [str(err)]
        return [], error_msg

    return obj.strs, error_msg


def get_c2config_report(parent_task):
    """
    This function retrieves the C2 configuration associated with the given task.

    [
        "ipv4_1:port1",
        "ipv4_2:port2",
        ...
    ]

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: C2 configuration and error message
    :rtype: tuple
    """
    data = set()
    error_msg = []

    try:
        objs = Configuration.objects.filter(parent_task=parent_task)
    except AttributeError as err:
        error_msg = [str(err)]
        return data, error_msg

    for obj in objs:
        data.add(f"{obj.ip}:{obj.port}")

    return list(data), error_msg


def get_dynamic_backend_report(submission_uuid, backend):
    """
    This function retrieves report for a specific backend in the dynamic analysis
    pipeline.

    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param backend: Backend name
    :type backend: str
    :return: Report for given backend and task UUID
    :rtype: dict
    """
    try:
        parent_task = TaskMetadata.objects.get(uuid=submission_uuid)
    except TaskMetadata.DoesNotExist:
        report = {"errors": True, "error_msg": ["Task not found"]}
        return report

    report = {"errors": False, "error_msg": [], "data": []}
    if backend:
        try:
            data, error_msg = globals()[f"get_{backend}_report"](parent_task)
        except AttributeError:
            return report

        report.update(
            {"errors": False, "error_msg": [], "data": data}
        )
        if error_msg:
            report.update({"errors": True, "error_msg": error_msg})
    else:
        report = {"errors": True, "error_msg": ["Unsupported backend"]}

    return report
