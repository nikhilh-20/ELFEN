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

import re
import datetime
from pathlib import Path
from analysis.analysis.utils.dynamic.extract_event_features import *
from analysis.analysis.utils.dynamic.parse_trace_logs import parse_ply_tracer_log,\
    parse_userland_tracer_log
from analysis.analysis.utils.dynamic.store_features import store_features_db

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def _extract_timestamp(item):
    item_fields = item.split(b",")
    try:
        return item_fields[1]
    except IndexError:
        LOG.error(f"Error during timestamp extraction for log item: {item}")
        raise IndexError


def read_userland_trace(tracers):
    """
    Read userland tracer log content to get the logs itself.

    :param tracers: Tracer file paths
    :type tracers: set
    :return: parsed tracer logs
    :rtype: list of bytes
    """
    LOG.debug(f"Reading userland trace logs")
    userland_trace_logfile = ""
    for t in tracers:
        if "userland.trace" in t:
            userland_trace_logfile = t
            break

    if userland_trace_logfile:
        LOG.debug(f"Reading userland trace logs from {userland_trace_logfile}")
        # I've come across cases where UTF-8 decoding results in a parsing error
        # because a given byte (ex: 0xf1) is not a valid representation of any
        # character in UTF-8. ISO-8859-1 has worked for me.
        with open(userland_trace_logfile, "r", encoding="ISO-8859-1") as f_:
            content = f_.read()
        return parse_userland_tracer_log(content)

    return []


def read_tracers(tracers):
    """
    Read tracer content into a list and sort it by timestamp.

    :param tracers: Tracer file paths
    :type tracers: set
    :return: Timestamp sorted list of all kernel and userland tracings
    :rtype: list of bytes, list of bytes
    """
    kernel_tracings = []
    userland_tracings = []

    userland_tracings_ = read_userland_trace(tracers)
    if userland_tracings_:
        LOG.debug("Userland traces found and parsed")
        userland_tracings.extend(userland_tracings_)

    for f in tracers:
        # I've come across cases where UTF-8 decoding results in a parsing error
        # because a given byte (ex: 0xf1) is not a valid representation of any
        # character in UTF-8. ISO-8859-1 has worked for me.
        with open(f, "r", encoding="ISO-8859-1") as f_:
            content = f_.read()
        tracer = os.path.splitext(os.path.basename(f))[0]
        LOG.debug(f"Processing {tracer} ply tracer logs")

        # Have to parse content in such a way that all trace lines belonging
        # to a function (OPEN, READ, etc.) should be accounted for irrespective
        # of any newlines that may occur in the middle of the trace line.
        # ply tracer output is not guaranteed to be on a single line.
        if tracer.lower() != "userland":
            kernel_tracings.extend(parse_ply_tracer_log(content, tracer))

    # Sort all_tracings according to timestamp
    LOG.debug("Sorting tracings by timestamp")
    userland_tracings.sort(key=_extract_timestamp)
    kernel_tracings.sort(key=_extract_timestamp)

    return kernel_tracings, userland_tracings


def extract_kernel_tracings_features(sample_filename, features, sorted_kernel_tracings):
    """
    Extract features from kernel tracings

    :param sample_filename: Sample filename in sandbox
    :type sample_filename: str
    :param features: Dictionary to populate with features
    :type features: dict
    :param sorted_kernel_tracings: Timestamp sorted list of all kernel tracings
    :type sorted_kernel_tracings: list of bytes
    :return: Dictionary populated with features
    :rtype: dict
    """
    LOG.debug(f"Extracting features from parsed ply traces")

    features["metadata"]["sample_pid"] = get_sample_pid(sample_filename, sorted_kernel_tracings)
    LOG.debug(f"Sample PID: {features['metadata']['sample_pid']}")
    relevant_pids = get_relevant_pids(features["metadata"]["sample_pid"], sorted_kernel_tracings)
    LOG.debug(f"Relevant PIDs: {relevant_pids}")

    for trace_line in sorted_kernel_tracings:
        # Below information are guaranteed to be present in every good trace line
        try:
            func = trace_line.split(b",")[0]
            # Datetime object is only able to get microseconds precision.
            # So, have to ignore nanoseconds component from the timestamp.
            # I don't think this should cause any issues.
            ts = datetime.datetime.strptime(trace_line.split(b",")[1].decode("utf-8")[:15],
                                            "%H:%M:%S.%f")
            # When YYYY-MM-DD is not present in the timestamp, then datetime
            # assumes it to Jan 1, 1970. So, have to replace it manually.
            today = datetime.datetime.today()
            ts = ts.replace(year=today.year, month=today.month, day=today.day)
            pid = int(trace_line.split(b",")[2])
            procname = trace_line.split(b",")[3]
        except (IndexError, ValueError):
            LOG.debug(f"Exception while parsing {trace_line}")
            # When a sample generates lots of syscalls, there is a chance that
            # the trace line is incomplete/corrupted. Skip such trace lines.
            continue

        # Remove irrelevant trace lines
        if pid not in relevant_pids or procname == get_orchestrator_filename():
            continue

        try:
            func_utf = func.decode("utf-8").lower()
            feature_ = {
                "func": func_utf,
                "ts": ts,
                "pid": pid,
                "procname": procname
            }
            feature_ = globals()[f"extract_{func_utf}_features"](trace_line, feature_)
        except (ValueError, KeyError) as err:
            LOG.error(f"Error while kernel behavior feature extraction: {err}. Trace line: {trace_line}")
            # Corruption in trace line. Skip
            continue

        if func in get_kernel_behavior_groups()["file_operations"]:
            features["syscalls"]["file_operations"].append(feature_)
        elif func in get_kernel_behavior_groups()["process_operations"]:
            features["syscalls"]["process_operations"].append(feature_)
        elif func in get_kernel_behavior_groups()["network_operations"]:
            features["syscalls"]["network_operations"].append(feature_)

    return features


def extract_userland_tracings_features(features, sorted_userland_tracings):
    """
    Extract features from userland tracings.

    :param features: Dictionary to populate with features
    :type features: dict
    :param sorted_userland_tracings: Timestamp sorted list of all userland tracings
    :type sorted_userland_tracings: list of bytes
    :return: Dictionary populated with features
    :rtype: dict
    """
    LOG.debug(f"Extracting features from parsed userland traces")
    for trace_line in sorted_userland_tracings:
        # Below information are guaranteed to be present in every trace line
        try:
            func = trace_line.split(b",")[0]
            # Datetime object is only able to get microseconds precision.
            # So, have to ignore nanoseconds component from the timestamp.
            # I don't think this should cause any issues.
            ts = datetime.datetime.fromtimestamp(int(trace_line.split(b",")[1].decode("utf-8")))
            procname = trace_line.split(b",")[2]
        except IndexError as err:
            # When a sample generates lots of syscalls, there is a chance that
            # the trace line is incomplete. Skip this trace line.
            LOG.error(f"IndexError while userland behavior feature extraction: {err}. Trace line: {trace_line}")
            continue

        try:
            func_utf = func.decode("utf-8").lower()
            feature_ = dict(func=func_utf, ts=ts, procname=procname)
            feature_ = globals()[f"extract_{func.decode('utf-8').lower()}_features"](trace_line, feature_)
        except (KeyError, UnicodeDecodeError) as err:
            LOG.error(f"Error while userland behavior feature extraction: {err}. Trace line: {trace_line}")
            # Corruption in trace line. Skip
            continue

        if func in get_userland_behavior_groups()["string_operations"]:
            features["userland"]["string_operations"].append(feature_)
        elif func in get_userland_behavior_groups()["memory_operations"]:
            features["userland"]["memory_operations"].append(feature_)

    return features


def extract_features(sample_filename, console_out, sorted_kernel_tracings,
                     sorted_userland_tracings):
    """
    Extract features from all tracings.

    :param sample_filename: Name of sample inside sandbox
    :type sample_filename: str
    :param console_out: Console output of sample
    :type console_out: bytes
    :param sorted_kernel_tracings: Timestamp sorted list of all kernel tracings
    :type sorted_kernel_tracings: list of bytes
    :param sorted_userland_tracings: Timestamp sorted list of all userland tracings
    :type sorted_userland_tracings: list of bytes
    :return: Dictionary populated with behavioral features
    :rtype: dict
    """
    LOG.debug(f"Extracting features from parsed trace lines")
    features = {
        "metadata": {
            "sample_filename": sample_filename,
            "console_out": console_out,
            "sample_pid": -1
        },
        "syscalls": {
            "file_operations": [],
            "process_operations": [],
            "network_operations": []
        },
        "userland": {
            "string_operations": [],
            "memory_operations": [],
        }
    }

    features = extract_kernel_tracings_features(sample_filename, features, sorted_kernel_tracings)
    return extract_userland_tracings_features(features, sorted_userland_tracings)


def analyze_trace(sample, dynamic_analysis_dir, task_reports):
    """
    Analyze the behavior of .trace files generated during dynamic analysis.

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param dynamic_analysis_dir: Host path where dynamic analysis artifacts
                                 will be stored
    :type dynamic_analysis_dir: str
    :param task_reports: Task reports object
    :type task_reports: analysis.models.TaskReports
    :return: Updated dynamic analysis report with features
    :rtype: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    """
    LOG.debug(f"Analyzing trace files in {dynamic_analysis_dir}")
    # consolidated_features = {}
    submission_uuid = os.path.basename(Path(dynamic_analysis_dir).parents[0])

    # This file stored the console output when the sample was executed
    console_out_fpath = os.path.join(dynamic_analysis_dir, "bin_output")
    try:
        LOG.debug(f"Reading console output from {console_out_fpath}")
        with open(console_out_fpath, "rb") as f:
            console_out = f.read()
        # If execution has failed for some reason, sometimes console_out may have
        # content of form: "/usr/bin/gogetit.sh: line <linenum>: ..."
        # In such cases, remove that irrelevant content
        console_out = re.sub(failed_exec_content(), b"", console_out)
    except FileNotFoundError:
        return None

    # Before dynamic analysis, the sample is renamed to a random string
    # This file stores that randomly generated filename
    sample_filename_fpath = os.path.join(dynamic_analysis_dir, "filename")
    try:
        LOG.debug(f"Reading sample filename from {sample_filename_fpath}")
        with open(sample_filename_fpath, "r") as f:
            sample_filename = f.read().strip()
    except FileNotFoundError:
        return None

    tracers = {os.path.join(dynamic_analysis_dir, f)
               for f in os.listdir(dynamic_analysis_dir)
               if f.endswith(".trace")}
    if tracers:
        LOG.debug(f"Found following tracers: {tracers}")
        sorted_kernel_tracings, sorted_userland_tracings = read_tracers(tracers)
    else:
        sorted_kernel_tracings, sorted_userland_tracings = [], []

    # Extract features from all tracings
    behavioral_features = extract_features(sample_filename, console_out,
                                           sorted_kernel_tracings,
                                           sorted_userland_tracings)

    # Store features to DB
    return store_features_db(sample, behavioral_features, submission_uuid, task_reports)
