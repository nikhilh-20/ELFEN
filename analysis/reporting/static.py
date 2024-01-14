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
from analysis.analysis_models.static_analysis import *
from analysis.reporting.utils.get_static_reports_values import *


def get_samplefeatures_report(parent_task):
    """
    This function retrieves SampleFeatures task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Sample features report and error message
    :rtype: tuple
    """
    data = []
    err_msg = []
    exclude_fields = ("errors", "error_msg", "status", "id",
                      "sample", "staticanalysisreports")
    try:
        obj = parent_task.taskreports.static_reports.samplefeatures
    except (AttributeError, SampleFeatures.DoesNotExist):
        return data, err_msg

    return get_samplefeatures_values(SampleFeatures, obj, exclude_fields)


def get_staticantianalysis_report(parent_task):
    """
    This function retrieves AntiStaticAnalysis task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Static anti-analysis report and error message
    :rtype: tuple
    """
    exclude_fields = ("errors", "error_msg", "status", "id",
                      "sample", "staticanalysisreports")
    return get_staticantianalysis_values(AntiStaticAnalysis, parent_task,
                                         "staticantianalysis", exclude_fields)


def get_staticantiantianalysis_report(parent_task):
    """
    This function retrieves AntiAntiStaticAnalysis task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Static anti-anti-analysis report and error message
    :rtype: tuple
    """
    exclude_fields = ("errors", "error_msg", "status", "id",
                      "sample", "staticanalysisreports")
    return get_staticantiantianalysis_values(AntiAntiStaticAnalysis, parent_task,
                                             "staticantiantianalysis", exclude_fields)


def get_capa_report(parent_task):
    """
    This function retrieves CAPA task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Capa capabilities report and error message
    :rtype: tuple
    """
    exclude_fields = ("errors", "error_msg", "status", "id",
                      "sample", "staticanalysisreports")
    return get_capa_values(CapaCapabilities, parent_task, "capa",
                           exclude_fields)


def get_elfheader_report(parent_task):
    """
    This function retrieves the ELFHeader task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: ELF header report and error message
    :rtype: tuple
    """
    data = []
    err_msg = []
    exclude_fields = ("errors", "error_msg", "status", "id", "sample",
                      "staticanalysisreports")
    try:
        obj = parent_task.taskreports.static_reports.elfheader
    except (AttributeError, ELFHeader.DoesNotExist):
        return data, err_msg

    return get_elfheader_values(ELFHeader, obj, exclude_fields)


def get_elfprogheader_report(parent_task):
    """
    This function retrieves the ELFProgramHeader task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: ELF program header report and error message
    :rtype: tuple
    """
    exclude_fields = ("errors", "error_msg", "status", "id", "sample",
                      "staticanalysisreports")
    return get_progheader_values(ELFProgramHeader, parent_task, exclude_fields)


def get_elfsectionheader_report(parent_task):
    """
    This function retrieves the ELFSectionHeader task data.

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: ELF section header report and error message
    :rtype: tuple
    """
    exclude_fields = ("errors", "error_msg", "status", "id", "sample",
                      "staticanalysisreports")
    return get_sectionheader_values(ELFSectionHeader, parent_task, exclude_fields)


def get_strings_report(parent_task):
    """
    This function retrieves printable strings extracted from the given sample.

    [str1, str2, ...]

    :param parent_task: Parent Task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Printable strings and error message
    :rtype: tuple
    """
    data = []
    error_msg = []

    try:
        obj = PrintableStrings.objects.get(sample=parent_task.sha256)
    except (AttributeError, PrintableStrings.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    return obj.strs, error_msg


def get_similarsamples_report(parent_task):
    """
    This function retrieves samples that are similar to the given sample.
    Clustering is done periodically using TLSH-based HAC-T algorithm.

    :param parent_task: Parent Task object
    :type parent_task: <class 'analysis.models.TaskMetadata'>
    :return: Similar samples' SHA256 and error message
    :rtype: tuple
    """
    error_msg = []

    try:
        data = parent_task.sha256.similar
    except (AttributeError, TaskMetadata.DoesNotExist,
            SampleMetadata.DoesNotExist):
        return [], []

    return data, error_msg


def get_static_backend_report(submission_uuid, backend):
    """
    This function retrieves report for a specific backend in the static analysis
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
