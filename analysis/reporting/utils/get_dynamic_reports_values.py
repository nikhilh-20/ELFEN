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

from analysis.reporting.enum import FilesystemEvents, ProcessEvents, NetworkEvents,\
    UserlandEvents


def _get_val(obj, model, base_fields, args):
    args_ = []
    data_ = {}

    for b in base_fields:
        val = getattr(obj, b)
        if b == "ts":
            val = f"{val.strftime('%H:%M:%S.%f')} UTC"
        if isinstance(val, memoryview):
            val = val.tobytes()
        data_[b] = val
    data_["func"] = model.__name__.split("Event")[0].lower()

    for a in args:
        val = getattr(obj, a)
        if isinstance(val, memoryview):
            val = val.tobytes()
        args_.append(f"{a}: {val}")

    args_ = "\n".join(args_)
    data_["args"] = args_
    return data_


def _parse_values(parent_task, event_type):
    """
    Parses the dynamic analysis report, extracts entries for the given
    event type (filesystem, network or process) and sorts by timestamp.

    [
        {
            "ts": "timestamp1", "pid": "pid1", "procname": "procname1",
            "func": "func1", "args": "args1", "ret": "ret1"
        },
        ...
    ]

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param event_type: Dictionary containing models/details for given event type
                       (filesystem, network or process)
    :type event_type: dict
    :return: Parsed entries for given event type and error message
    :rtype: tuple
    """
    sample = parent_task.sha256
    kernel_trace = parent_task.taskreports.dynamic_reports.kernel_trace

    data = []
    error_msg = []
    base_fields = ["ts", "pid", "procname"]

    for model in event_type:
        args = event_type[model]["args"]
        ret = event_type[model]["ret"]

        for obj in model.objects.filter(sample=sample, kernel_trace=kernel_trace):
            data_ = _get_val(obj, model, base_fields, args)

            if ret:
                data_["ret"] = getattr(obj, ret)
            else:
                data_["ret"] = ""

            data.append(data_)

    # Sort by timestamp
    return sorted(data, key=lambda x: x["ts"]), error_msg


def get_fileops_values(parent_task):
    """
    Gets filesystem related events from the dynamic analysis report.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: File operations report and error message
    :rtype: tuple
    """
    return _parse_values(parent_task, FilesystemEvents)


def get_procops_values(parent_task):
    """
    Gets process related events from the dynamic analysis report.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Process operations report and error message
    :rtype: tuple
    """
    return _parse_values(parent_task, ProcessEvents)


def get_netops_values(parent_task):
    """
    Gets network related events from the dynamic analysis report.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Network operations report and error message
    :rtype: tuple
    """
    return _parse_values(parent_task, NetworkEvents)


def get_userland_values(parent_task):
    """
    Parses the dynamic analysis report, extracts entries related to userland
    events and sorts by timestamp.

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Userland operations report and error message
    :rtype: tuple
    """
    sample = parent_task.sha256
    userland_trace = parent_task.taskreports.dynamic_reports.userland_trace
    data = []
    error_msg = []
    base_fields = ["ts", "procname"]

    for model in UserlandEvents:
        args = UserlandEvents[model]["args"]
        for obj in model.objects.filter(sample=sample, userland_trace=userland_trace):
            args_ = _get_val(obj, model, base_fields, args)
            data.append(args_)

    # Sort by timestamp
    return sorted(data, key=lambda x: x["ts"]), error_msg
