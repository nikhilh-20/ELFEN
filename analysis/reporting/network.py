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

from analysis.models import TaskMetadata
from analysis.reporting.utils.get_network_reports_values import *


def get_pcapanalysis_report(parent_task):
    """
    This function retrieves the pcap analysis data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: PCAP analysis report and error message
    :rtype: dict, list
    """
    return get_pcap_analysis_values(parent_task)


def get_network_backend_report(submission_uuid, backend):
    """
    This function retrieves report for a specific backend in the network analysis
    pipeline.

    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param backend: Backend name
    :type backend: str
    :return: Analysis report for a given backend and task UUID
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
