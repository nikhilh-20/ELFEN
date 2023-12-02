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
from analysis.analysis_models.dynamic_analysis import *

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


USERLAND_MODEL_MAPPINGS = {
    "strcmp": {
        "model": StrcmpEvent,
        "event_fields": ["ts", "procname", "str1", "str2"]
    },
    "strncmp": {
        "model": StrncmpEvent,
        "event_fields": ["ts", "procname", "str1", "str2", "len"]
    },
    "strstr": {
        "model": StrstrEvent,
        "event_fields": ["ts", "procname", "haystack", "needle"]
    },
    "strcpy": {
        "model": StrcpyEvent,
        "event_fields": ["ts", "procname", "src"]
    },
    "strncpy": {
        "model": StrncpyEvent,
        "event_fields": ["ts", "procname", "src", "len"]
    },
}

SYSCALL_MODEL_MAPPINGS = {
    "fork": {
        "model": ForkEvent,
        "event_fields": ["ts", "pid", "procname", "retval"]
    },
    "getpid": {
        "model": GetPidEvent,
        "event_fields": ["ts", "pid", "procname", "retval"]
    },
    "getppid": {
        "model": GetPPidEvent,
        "event_fields": ["ts", "pid", "procname", "retval"]
    },
    "execve": {
        "model": ExecveEvent,
        "event_fields": ["ts", "pid", "procname", "exec_path", "arg1", "arg2"]
    },
    "prctl": {
        "model": PrctlEvent,
        "event_fields": ["ts", "pid", "procname", "option", "arg2",
                         "arg3", "arg4", "arg5"]
    },
    "read": {
        "model": ReadEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "buffer", "size"]
    },
    "write": {
        "model": WriteEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "buffer", "size"]
    },
    "open": {
        "model": OpenEvent,
        "event_fields": ["ts", "pid", "procname", "file_path", "flags", "fd"]
    },
    "rename": {
        "model": RenameEvent,
        "event_fields": ["ts", "pid", "procname", "oldfile_path", "newfile_path"]
    },
    "readlink": {
        "model": ReadlinkEvent,
        "event_fields": ["ts", "pid", "procname", "file_path", "buffer", "retval"]
    },
    "unlink": {
        "model": UnlinkEvent,
        "event_fields": ["ts", "pid", "procname", "file_path"]
    },
    "fcntl": {
        "model": FcntlEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "cmd", "arg"]
    },
    "socket": {
        "model": SocketEvent,
        "event_fields": ["ts", "pid", "procname", "domain", "type", "protocol", "fd"]
    },
    "setsockopt": {
        "model": SetSockOptEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "level", "option_name",
                         "option_value", "option_len"]
    },
    "bind": {
        "model": BindEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "family", "ip", "port", "retval"]
    },
    "connect": {
        "model": ConnectEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "family", "ip", "port", "retval"]
    },
    "listen": {
        "model": ListenEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "backlog"]
    },
    "sendto": {
        "model": SendToEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "buffer", "size"]
    },
    "recvfrom": {
        "model": RecvFromEvent,
        "event_fields": ["ts", "pid", "procname", "fd", "buffer", "size"]
    },
}


def _update_kernel_event(sample, kernel_trace, feature_, event_fields, event_model):
    """
    This function stores specified fields of a kernel event in the database.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param kernel_trace: KernelTrace object
    :type kernel_trace: analysis.analysis_models.dynamic_analysis.KernelTrace
    :param feature_: Feature dictionary
    :type feature_: dict
    :param event_fields: List of fields to store
    :type event_fields: list
    :param event_model: Event model
    :type event_model: django.db.models.base.ModelBase
    :return: Updated event object
    :rtype: analysis.analysis_models.dynamic_analysis.??Event
    """
    event_obj = event_model(sample=sample, kernel_trace=kernel_trace)
    for f in event_fields:
        setattr(event_obj, f, feature_[f])
    return event_obj


def _update_userland_event(sample, userland_trace, feature_, event_fields, event_model):
    """
    This function stores specified fields of an userland event in the database.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param userland_trace: UserlandTrace object
    :type userland_trace: analysis.analysis_models.dynamic_analysis.UserlandTrace
    :param feature_: Feature dictionary
    :type feature_: dict
    :param event_fields: List of fields to store
    :type event_fields: list
    :param event_model: Event model
    :type event_model: django.db.models.base.ModelBase
    :return: Updated event object
    :rtype: analysis.analysis_models.dynamic_analysis.??Event
    """
    event_obj = event_model(sample=sample, userland_trace=userland_trace)
    for f in event_fields:
        setattr(event_obj, f, feature_[f])
    return event_obj


def store_userland_trace(sample, userland_features):
    """
    Store userland trace (from ELFEN.so) in database.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param userland_features: Dictionary of userland features collected by ELFEN.so
    :type userland_features: dict
    :return: Userland trace object
    :rtype: analysis.analysis_models.dynamic_analysis.UserlandTrace
    """
    LOG.debug(f"Storing userland trace in database")
    userland_trace = UserlandTrace.objects.create()

    event_objs = {func: [] for func in USERLAND_MODEL_MAPPINGS}
    for syscall_group in userland_features:
        for syscall_info in userland_features[syscall_group]:
            func = syscall_info["func"]
            event_fields = USERLAND_MODEL_MAPPINGS[func]["event_fields"]
            event_model = USERLAND_MODEL_MAPPINGS[func]["model"]
            obj = _update_userland_event(sample, userland_trace, syscall_info, event_fields, event_model)
            event_objs[func].append(obj)

    LOG.debug(f"Committing database objects")
    # Mass commit to DB
    for func in event_objs:
        func_obj_list = event_objs[func]
        model = USERLAND_MODEL_MAPPINGS[func]["model"]
        model.objects.bulk_create(func_obj_list)

    return userland_trace


def store_kernel_trace(sample, syscalls_features):
    """
    Store kernel trace (ply events) in database.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param syscalls_features: Dictionary of syscall features collected by ply
    :type syscalls_features: dict
    :return: KernelTrace object
    :rtype: analysis.analysis_models.dynamic_analysis.KernelTrace
    """
    LOG.debug(f"Storing kernel trace in database")
    kernel_trace = KernelTrace.objects.create()

    event_objs = {func: [] for func in SYSCALL_MODEL_MAPPINGS}
    for syscall_group in syscalls_features:
        for syscall_info in syscalls_features[syscall_group]:
            func = syscall_info["func"]
            event_fields = SYSCALL_MODEL_MAPPINGS[func]["event_fields"]
            event_model = SYSCALL_MODEL_MAPPINGS[func]["model"]
            obj = _update_kernel_event(sample, kernel_trace, syscall_info, event_fields, event_model)
            event_objs[func].append(obj)

    # Mass commit to DB
    LOG.debug(f"Committing database objects")
    for func in event_objs:
        func_obj_list = event_objs[func]
        model = SYSCALL_MODEL_MAPPINGS[func]["model"]
        model.objects.bulk_create(func_obj_list)

    return kernel_trace


def store_features_db(sample, behavioral_features, submission_uuid, task_reports):
    """
    Store features in database.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param behavioral_features: Dictionary of behavioral features
    :type behavioral_features: dict
    :param submission_uuid: UUID of submission
    :type submission_uuid: str
    :param task_reports: Task reports object
    :type task_reports: analysis.models.TaskReports
    :return: Updated dynamic analysis report
    :rtype: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    """
    LOG.debug(f"Storing behavioral features in database for submission {submission_uuid}")
    LOG.debug(f"Task reports: {task_reports}")
    dynamic_analysis_report = task_reports.dynamic_reports
    LOG.debug(f"Dynamic analysis report: {dynamic_analysis_report}")

    # Store behavioral artifacts
    dynamic_analysis_report.metadata = DynamicAnalysisMetadata.objects.create(
                                           sample=sample,
                                           filename=behavioral_features["metadata"]["sample_filename"],
                                           console_output=behavioral_features["metadata"]["console_out"],
                                           sample_pid=behavioral_features["metadata"]["sample_pid"]
                                       )
    dynamic_analysis_report.kernel_trace = store_kernel_trace(sample, behavioral_features.get("syscalls", {}))
    dynamic_analysis_report.userland_trace = store_userland_trace(sample, behavioral_features.get("userland", {}))

    dynamic_analysis_report.save(update_fields=["metadata", "kernel_trace", "userland_trace"])
    LOG.debug(f"Stored behavioral features in database for submission {submission_uuid}")
    return dynamic_analysis_report
