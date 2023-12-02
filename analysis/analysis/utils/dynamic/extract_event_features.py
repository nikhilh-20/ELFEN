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
import socket
import struct
import logging

from analysis.analysis_models.utils import USERLAND_STR_MAXLEN

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


# When changing the 4 dicts below, also update SYSCALL_MODEL_MAPPINGS()
# in store_features.py and reporting/enum.py
# The below keys represent the event/function name and the values represent
# the number of comma-separated tokens expected in the respective trace entry.
FILEOPS_EVENTS = {
    b"OPEN": [7],
    b"READ": [7],
    b"WRITE": [7],
    b"READLINK": [7],
    b"UNLINK": [5],
    b"RENAME": [6],
}

PROCOPS_EVENTS = {
    b"FORK": [5],
    b"GETPID": [5],
    b"GETPPID": [5],
    b"PRCTL": [6, 9],
    b"EXECVE": [7]
}

FCNTLOPS_EVENTS = {
    b"FCNTL": [7]
}

NETOPS_EVENTS = {
    b"SOCKET": [8],
    b"SETSOCKOPT": [9],
    b"BIND": [9],
    b"CONNECT": [9],
    b"LISTEN": [6],
}

NETCOMMS_EVENTS = {
    b"SENDTO": [7],
    b"RECVFROM": [7],
}

# When changing this set, also update reporting/enum.py and
# USERLAND_MODEL_MAPPINGS in store_features.py
STR_USERLAND_EVENTS = {
    b"STRCMP", b"STRNCMP", b"STRSTR", b"STRCPY", b"STRNCPY"
}

# Avoid parsing libc function trace from these binaries
USERLAND_IGNORE_BINARIES = {
    b"esxcli", b"sh", b"xargs", b"awk"
}


def get_orchestrator_filename():
    return rb"gogetit.sh"


def failed_exec_content():
    return rb"/usr/bin/" + get_orchestrator_filename() + rb": line \d+: "


def get_ply_kallsyms_str():
    return b"info: creating kallsyms cache"


def get_ply_events_lost_substr():
    return b"warning: lost"


def get_tracer_dir():
    return b"/usr/lib/tracers"


def get_memdump_dir():
    return b"/usr/lib/memdump"


def get_elfen_lib():
    return b"elfen.so"


def get_memdump_reader():
    return b"memreader.py"


def get_kernel_behavior_groups():
    """
    Gets behavior groups and syscall mapping.

    :return: Behavior groups and syscall mapping
    :rtype: dict
    """
    return {
        "file_operations": list(FCNTLOPS_EVENTS.keys()) + list(FILEOPS_EVENTS.keys()),
        "process_operations": list(PROCOPS_EVENTS.keys()),
        "network_operations": list(NETOPS_EVENTS.keys()) + list(NETCOMMS_EVENTS.keys())
    }


def get_userland_behavior_groups():
    """
    Gets behavior groups and function mapping.

    :return: Behavior groups and syscall mapping
    :rtype: dict
    """
    return {"string_operations": STR_USERLAND_EVENTS}


def get_relevant_pids(sample_pid, sorted_all_tracings):
    """
    Get PIDs that are associated with the sample and any processes that it
    creates.

    :param sample_pid: PID of the sample
    :type sample_pid: int
    :param sorted_all_tracings: Timestamp-sorted list of all tracings
    :type sorted_all_tracings: list of tuples
    :return: PIDs relevant to the sample
    :rtype: set
    """
    LOG.debug(f"Getting relevant PIDs")
    relevant_pids = {sample_pid}

    for trace_line in sorted_all_tracings:
        func = trace_line.split(b",")[0]

        if func in get_kernel_behavior_groups()["process_operations"]:
            if func == b"FORK":
                LOG.debug("Fork event found")
                fork_features = extract_fork_features(trace_line)
                pid = fork_features["pid"]
                if not pid:
                    # Unexpected trace line
                    continue
                if pid in relevant_pids:
                    child_pid = fork_features["retval"]
                    if child_pid is None:
                        # Unexpected trace line
                        continue
                    child_pid = int(child_pid)
                    LOG.debug(f"Relevant PID: {child_pid}")
                    relevant_pids.add(child_pid)
                    continue

    return relevant_pids


def get_sample_pid(sample_filename, sorted_all_tracings):
    """
    Gets the sample PID from the tracer output. When the orchestrator is launched
    from shell, it forks and then launches the sample with execve. The PID of the
    forked orchestrator process is the sample PID. Note that execve replaced the
    image, so a new PID is not created.

    :param sample_filename: Sample filename in sandbox
    :type sample_filename: str
    :param sorted_all_tracings: Timestamp sorted list of all tracings
    :type sorted_all_tracings: list of bytes
    :return: Sample PID, or -1 if not found
    :rtype: int
    """
    LOG.debug("Getting sample PID")
    orchestrator_filename = get_orchestrator_filename()

    for t in sorted_all_tracings:
        # Look for first occurrence only
        # Ex: EXECVE,02:08:19.909998986,149,gogetit.sh,./FESEaU5X,,
        if (b"EXECVE" == t.split(b",")[0] and orchestrator_filename in t
                and sample_filename.encode() in t):
            LOG.debug(f"Found target execve event: {t}")
            return int(t.split(b",")[2])

    return -1


def extract_strcmp_features(strcmp_trace_line, feature_=None):
    """
    Given a trace line for a strcmp user call, extract relevant features:
    compared strings

    An example trace line is:
    STRCMP,1691227157,esxcli,vm,vm
    This is of format:
    function_name,timestamp,procname,str1,str2

    :param strcmp_trace_line: Trace line for strcmp function
    :type strcmp_trace_line: bytes
    :param feature_: Already extracted features: event name, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = strcmp_trace_line.strip(b"\n").split(b",")

    try:
        # Necessary to truncate for Golang-kind of samples where
        # strings are not null-terminated
        feature_.update({
            "str1": tokens[3].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN],
            "str2": tokens[4].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN]
        })
    except IndexError:
        LOG.error(f"Unexpected strcmp trace line: {strcmp_trace_line}")
        feature_.update({
            "str1": None,
            "str2": None
        })
        return feature_

    LOG.debug(f"Extracted strcmp features: {feature_}")
    return feature_


def extract_strncmp_features(strncmp_trace_line, feature_=None):
    """
    Given a trace line for a strncmp user call, extract relevant features:
    compared strings and length

    An example trace line is:
    STRNCMP,1691227217,uApsio3b,nvram,.vmdk,5
    This is of format:
    function_name,timestamp,procname,str1,str2,length

    :param strncmp_trace_line: Trace line for strncmp function
    :type strncmp_trace_line: bytes
    :param feature_: Already extracted features: event name, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = strncmp_trace_line.strip(b"\n").split(b",")

    try:
        # Necessary to truncate for Golang-kind of samples where
        # strings are not null-terminated
        feature_.update({
            "str1": tokens[3].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN],
            "str2": tokens[4].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN],
            "len": int(tokens[5].decode("ISO-8859-1"))
        })
    except (IndexError, ValueError):
        LOG.error(f"Unexpected strncmp trace line: {strncmp_trace_line}")
        feature_.update({
            "str1": None,
            "str2": None,
            "len": None
        })
        return feature_

    LOG.debug(f"Extracted strncmp features: {feature_}")
    return feature_


def extract_strstr_features(strstr_trace_line, feature_=None):
    """
    Given a trace line for a strstr usercall, extract relevant features:
    string and substring being searched for.

    An example trace line is:
    STRSTR,1691227277,uApsio3b,/root/guild,vmfs
    This is of format:
    function_name,timestamp,procname,string,substring_to_search

    :param strstr_trace_line: Trace line for strstr function
    :type strstr_trace_line: bytes
    :param feature_: Already extracted features: event name, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = strstr_trace_line.strip(b"\n").split(b",")

    try:
        # Necessary to truncate for Golang-kind of samples where
        # strings are not null-terminated
        feature_.update({
            "haystack": tokens[3].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN],
            "needle": tokens[4].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN]
        })
    except IndexError:
        LOG.error(f"Unexpected strstr trace line: {strstr_trace_line}")
        feature_.update({
            "haystack": None,
            "needle": None
        })
        return feature_

    LOG.debug(f"Extracted strstr features: {feature_}")
    return feature_


def extract_strcpy_features(strcpy_trace_line, feature_=None):
    """
    Given a trace line for a strcpy user call, extract relevant features:
    bytes at source address.

    An example trace line is:
    STRCPY,1691227337,uApsio3b,/vmfs/volumes
    This is of format:
    function_name,timestamp,procname,src

    :param strcpy_trace_line: Trace line for strcpy function
    :type strcpy_trace_line: bytes
    :param feature_: Already extracted features: event name, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = strcpy_trace_line.strip(b"\n").split(b",")

    try:
        # Necessary to truncate for Golang-kind of samples where
        # strings are not null-terminated
        feature_.update({
            "src": tokens[3].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN],
        })
    except IndexError:
        LOG.error(f"Unexpected strcpy trace line: {strcpy_trace_line}")
        feature_.update({
            "src": None
        })
        return feature_

    LOG.debug(f"Extracted strcpy features: {feature_}")
    return feature_


def extract_strncpy_features(strncpy_trace_line, feature_=None):
    """
    Given a trace line for a strncpy user call, extract relevant features:
    bytes at source address, number of bytes to copy.

    An example trace line is:
    STRNCPY,1691227397,uApsio3b,/vmfs/volumes,6
    This is of format:
    function_name,timestamp,procname,src,length

    :param strncpy_trace_line: Trace line for strncpy function
    :type strncpy_trace_line: bytes
    :param feature_: Already extracted features: event name, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = strncpy_trace_line.strip(b"\n").split(b",")

    try:
        # Necessary to truncate for Golang-kind of samples where
        # strings are not null-terminated
        feature_.update({
            "src": tokens[3].decode("ISO-8859-1")[:USERLAND_STR_MAXLEN],
            "len": int(tokens[4].decode("ISO-8859-1"))
        })
    except (ValueError, IndexError):
        LOG.error(f"Unexpected strncpy trace line: {strncpy_trace_line}")
        feature_.update({
            "src": None,
            "len": None
        })
        return feature_

    LOG.debug(f"Extracted strncpy features: {feature_}")
    return feature_


def extract_fork_features(fork_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a fork syscall, extract child process PID.

    An example trace line is:
    FORK,01:45:39.845535954,114,gogetit.sh,132
    This is of format:
    syscall_name,timestamp,process_id,process_name,child_process_id

    :param fork_trace_line: Trace line for fork syscall
    :type fork_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = fork_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({"pid": int(tokens[2]), "retval": int(tokens[4])})
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected FORK trace line: {fork_trace_line}")
        feature_.update({"retval": None, "pid": None})
        return feature_

    LOG.debug(f"Extracted fork features: {feature_}")
    return feature_


def extract_getpid_features(getpid_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a getpid syscall, extract current process ID

    An example trace line is:
    GETPID,01:45:39.848182580,132,gogetit.sh,132
    This is of format:
    syscall_name,timestamp,process_id,process_name,current_process_id

    :param getpid_trace_line: Trace line for getpid syscall
    :type getpid_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = getpid_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({"retval": int(tokens[4])})
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected GETPID trace line: {getpid_trace_line}")
        feature_.update({"retval": None})
        return feature_

    LOG.debug(f"Extracted getpid features: {feature_}")
    return feature_


def extract_getppid_features(getppid_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a getppid syscall, extract parent process ID

    An example trace line is:
    GETPPID,01:45:39.848182580,132,gogetit.sh,112
    This is of format:
    syscall_name,timestamp,process_id,process_name,parent_process_id

    :param getppid_trace_line: Trace line for getppid syscall
    :type getppid_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = getppid_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({"retval": int(tokens[4])})
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected GETPPID trace line: {getppid_trace_line}")
        feature_.update({"retval": None})
        return feature_

    LOG.debug(f"Extracted getppid features: {feature_}")
    return feature_


def extract_execve_features(execve_trace_line, endian=None, feature_=None):
    """
    Given a trace line for an execve syscall, extract executed file path

    An example trace line is:
    EXECVE,05:58:41.427908271,152,xargs,./HjfrEzf1,1,/vmfs/volumes
    This is of format:
    syscall_name,timestamp,process_id,process_name,executed_file_path,arg1,arg2

    :param execve_trace_line: Trace line for execve syscall
    :type execve_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = execve_trace_line.strip(b"\n").split(b",")

    try:
        # TODO: execve may get more cmdline arguments but ply allows
        #  me to extract only the first two
        feature_.update({"exec_path": tokens[4], "arg1": tokens[5],
                         "arg2": tokens[6]})
    except IndexError:
        # Unexpected trace line
        LOG.error(f"Unexpected EXECVE trace line: {execve_trace_line}")
        feature_.update({"exec_path": None, "arg1": None, "arg2": None})
        return feature_

    LOG.debug(f"Extracted execve features: {feature_}")
    return feature_


def extract_prctl_features(prctl_trace_line, endian=None, feature_=None):
    """
    Given a trace line for prctl syscall, extract option, arg2 and
    other arguments, if applicable.

    An example trace line is:
    PRCTL,01:30:08.030527965,145,HUGzJy5q,15,
    This is of format:
    syscall_name,timestamp,process_id,process_name,option,arg2,arg3,arg4,arg5

    :param prctl_trace_line: Trace line for prctl syscall
    :type prctl_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = prctl_trace_line.strip(b"\n").split(b",")

    try:
        if len(tokens) == 6:
            feature_.update({"option": tokens[4], "arg2": tokens[5],
                             "arg3": None, "arg4": None,
                             "arg5": None})
        elif len(tokens) == 9:
            feature_.update({"option": tokens[4], "arg2": tokens[5],
                             "arg3": tokens[6], "arg4": tokens[7],
                             "arg5": tokens[8]})
        elif len(tokens) == 8:
            # MIPS
            feature_.update({"option": tokens[4], "arg2": str(tokens[5]),
                             "arg3": tokens[6], "arg4": tokens[7]})
        else:
            LOG.error(f"Unexpected number of tokens in PRCTL trace line: {prctl_trace_line}")
            return feature_
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected PRCTL trace line: {prctl_trace_line}")
        feature_.update({"option": None, "arg2": None,
                         "arg3": None, "arg4": None,
                         "arg5": None})
        return feature_

    LOG.debug(f"Extracted prctl features: {feature_}")
    return feature_


def extract_read_features(read_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a read syscall, extract relevant features:
    File descriptor, Buffer, Number of bytes to read

    An example trace line is:
    READ,06:31:26.496491992,153,LLhSVE14,3,\\x7fELF\\x02\\x01\\x01,832
    This is of format:
    syscall_name,timestamp,process_id,process_name,fd,buffer,num_bytes_to_read

    :param read_trace_line: Trace line for read syscall
    :type read_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = read_trace_line.strip(b"\n").split(b",")

    try:
        num_bytes_to_read = int(tokens[6])
        feature_.update({
            "fd": int(tokens[4]),
            # I read 64 bytes by default inside the tracer, so if num_bytes_to_read
            # is less than 64, than I'll show the appropriate number of bytes to
            # the user.
            "buffer": tokens[5][:num_bytes_to_read],
            "size": num_bytes_to_read
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected READ trace line: {read_trace_line}")
        feature_.update({"fd": None, "buffer": None, "size": None})
        return feature_

    LOG.debug(f"Extracted read features: {feature_}")
    return feature_


def extract_write_features(write_trace_line, endian=None, feature_=None):
    """
    Given a trace line for write syscall, extract relevant features:
    File descriptor, Buffer, Number of bytes to write

    An example trace line is:
    WRITE,01:45:40.118237044,88,syslogd,3,July  5 01:45:40 kela kern.info kernel:[    7.306173] clocksourc,135\n
    This is of format:
    syscall_name,timestamp,process_id,process_name,fd,buffer,num_bytes_to_write

    :param write_trace_line: Trace line for write syscall
    :type write_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = write_trace_line.strip(b"\n").split(b",")

    try:
        num_bytes_to_write = int(tokens[6])
        feature_.update({
            "fd": int(tokens[4]),
            # I read 64 bytes by default inside the tracer, so if num_bytes_to_write
            # is less than 64, than I'll show the appropriate number of bytes to
            # the user.
            "buffer": tokens[5][:num_bytes_to_write],
            "size": num_bytes_to_write
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected WRITE trace line: {write_trace_line}")
        feature_.update({"fd": None, "buffer": None, "size": None})
        return feature_

    LOG.debug(f"Extracted write features: {feature_}")
    return feature_


def extract_readlink_features(readlink_trace_line, endian=None, feature_=None):
    """
    Given a trace line for readlink syscall, extract relevant features:
    file_path, buffer, retval

    An example trace line is:
    READLINK,00:01:21.987306965,148,g5aahcee1benee3,/proc/148/exe,/root/guild/rNC3zvLL,20
    This is of format:
    syscall_name,timestamp,process_id,process_name,file_path,buffer,num_bytes_written_to_buffer

    :param readlink_trace_line: Trace line for readlink syscall
    :type readlink_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, timestamp, PID, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = readlink_trace_line.strip(b"\n").split(b",")

    try:
        num_bytes_written_to_buffer = int(tokens[6])
        feature_.update({
            "file_path": tokens[4],
            # I read 64 bytes by default inside the tracer, so if num_bytes_written_to_buffer
            # is less than 64, than I'll show the appropriate number of bytes to
            # the user.
            "buffer": tokens[5][:num_bytes_written_to_buffer],
            "retval": num_bytes_written_to_buffer
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected READLINK trace line: {readlink_trace_line}")
        feature_.update({"file_path": None, "buffer": None, "retval": None})
        return feature_

    LOG.debug(f"Extracted readlink features: {feature_}")
    return feature_


def extract_unlink_features(unlink_trace_line, endian=None, feature_=None):
    """
    Given a trace line for unlink syscall, extract file_path

    An example trace line is:
    UNLINK,00:01:21.987306965,148,g5aahcee1benee3,/root/guild/rNC3zvLL
    This is of format:
    syscall_name,timestamp,process_id,process_name,file_path

    :param unlink_trace_line: Trace line for unlink syscall
    :type unlink_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = unlink_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "file_path": tokens[4],
        })
    except IndexError:
        # Unexpected trace line
        LOG.error(f"Unexpected UNLINK trace line: {unlink_trace_line}")
        feature_.update({"file_path": None})
        return feature_

    LOG.debug(f"Extracted unlink features: {feature_}")
    return feature_


def extract_open_features(open_trace_line, endian=None, feature_=None):
    """
    Given a trace line for an open syscall, extract relevant features:
    File path, Flags, File descriptor

    An example trace line is:
    OPEN,01:45:39.862177229,132,UItuj9gX,/etc/ld.so.cache,557056,-2
    This is of format:
    syscall_name,timestamp,process_id,process_name,file_path,flags,fd

    :param open_trace_line: Trace line for open syscall
    :type open_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = open_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "file_path": tokens[4],
            "flags": int(tokens[5]),
            "fd": int(tokens[6])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected OPEN trace line: {open_trace_line}")
        feature_.update({"file_path": None, "flags": None, "fd": None})
        return feature_

    LOG.debug(f"Extracted open features: {feature_}")
    return feature_


def extract_rename_features(rename_trace_line, endian=None, feature_=None):
    """
    Given a trace line for unlink syscall, extract file_path

    An example trace line is:
    RENAME,03:19:08.462642280,149,thread-pool-0,/path/ycsKHWLf.vmx,/path/ycsKHWLf.vmx.Cylance
    This is of format:
    syscall_name,timestamp,process_id,process_name,oldfile_path,newfile_path

    :param rename_trace_line: Trace line for rename syscall
    :type rename_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = rename_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "oldfile_path": tokens[4],
            "newfile_path": tokens[5],
        })
    except IndexError:
        # Unexpected trace line
        LOG.error(f"Unexpected RENAME trace line: {rename_trace_line}")
        feature_.update({"oldfile_path": None, "newfile_path": None})
        return feature_

    LOG.debug(f"Extracted rename features: {feature_}")
    return feature_


def extract_fcntl_features(fcntl_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a fcntl syscall, extract relevant features:
    File descriptor, Command, Argument

    An example trace line is:
    FCNTL,01:45:39.862177229,132,UItuj9gX,3,2,0
    This is of format:
    syscall_name,timestamp,process_id,process_name,fd,command,argument

    :param fcntl_trace_line: Trace line for fcntl syscall
    :type fcntl_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = fcntl_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "fd": int(tokens[4]),
            "cmd": int(tokens[5]),
            "arg": int(tokens[6])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected FCNTL trace line: {fcntl_trace_line}")
        feature_.update({"fd": None, "cmd": None, "arg": None})
        return feature_

    LOG.debug(f"Extracted fcntl features: {feature_}")
    return feature_


def extract_socket_features(socket_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a socket syscall, extract relevant features:
    domain, type, protocol, socket fd

    An example trace line is:
    SOCKET,10:39:03.027813163,143,MKyRatv8,2,1,0,4
    This is of format:
    syscall_name,timestamp,process_id,process_name,domain,type,protocol,socket_fd

    :param socket_trace_line: Trace line for socket syscall
    :type socket_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = socket_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "domain": int(tokens[4]),
            "type": int(tokens[5]),
            "protocol": int(tokens[6]),
            "fd": int(tokens[7])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected SOCKET trace line: {socket_trace_line}")
        feature_.update({"domain": None, "type": None, "protocol": None,
                         "fd": None})
        return feature_

    LOG.debug(f"Extracted socket features: {feature_}")
    return feature_


def extract_setsockopt_features(setsockopt_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a setsockopt syscall, extract relevant features:
    socket fd, level, option_name, option_value

    An example trace line is:
    SETSOCKOPT,20:00:31.763645717,154,e2eytxeV,3,1,2,\\x01,4
    This is of format:
    syscall_name,timestamp,process_id,process_name,socket_fd,level,option_name,option_value,option_value

    :param setsockopt_trace_line: Trace line for setsockopt syscall
    :type setsockopt_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = setsockopt_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "fd": int(tokens[4]),
            "level": int(tokens[5]),
            "option_name": int(tokens[6]),
            "option_value": tokens[7],
            "option_len": int(tokens[8])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected SETSOCKOPT trace line: {setsockopt_trace_line}")
        feature_.update({"fd": None, "level": None, "option_name": None,
                         "option_value": None, "option_len": None})
        return feature_

    LOG.debug(f"Extracted setsockopt features: {feature_}")
    return feature_


def extract_bind_features(bind_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a bind syscall, extract relevant features:
    socket fd, address family, port, ip, return value.
    IP address and port number are in network byte order in log entry.

    An example trace line is:
    BIND,10:39:00.294967373,143,MKyRatv8,4,2,16777343,24337,0
    This is of format:
    syscall_name,timestamp,process_id,process_name,socket_fd,address_family,ip,port,retval

    :param bind_trace_line: Trace line for bind syscall
    :type bind_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = bind_trace_line.strip(b"\n").split(b",")

    try:
        if endian == "BE":
            ip = socket.inet_ntoa(struct.pack("!L", int(tokens[6])))
            port = int(tokens[7])
        else:
            ip = socket.inet_ntoa(struct.pack("<L", int(tokens[6])))
            port = socket.ntohs(int(tokens[7]))

        feature_.update({
            "fd": int(tokens[4]),
            "family": int(tokens[5]),
            "ip": ip,
            "port": port,
            "retval": int(tokens[8])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected BIND trace line: {bind_trace_line}")
        feature_.update({"fd": None, "family": None, "ip": None,
                         "port": None, "retval": None})
        return feature_

    LOG.debug(f"Extracted bind features: {feature_}")
    return feature_


def extract_connect_features(connect_trace_line, endian=None, feature_=None):
    """
    Given a trace line for connect syscall, extract relevant features:
    socket fd, address family, port, ip, return value.
    IP address and port number are in network byte order in log entry.

    An example trace line is:
    CONNECT,10:39:03.030701375,143,MKyRatv8,4,2,134744072,13568,-101
    This is of format:
    syscall_name,timestamp,process_id,process_name,socket_fd,address_family,ip,port,retval

    :param connect_trace_line: Trace line for connect syscall
    :type connect_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = connect_trace_line.strip(b"\n").split(b",")

    try:
        if endian == "BE":
            ip = socket.inet_ntoa(struct.pack("!L", int(tokens[6])))
            port = int(tokens[7])
        else:
            ip = socket.inet_ntoa(struct.pack("<L", int(tokens[6])))
            port = socket.ntohs(int(tokens[7]))

        feature_.update({
            "fd": int(tokens[4]),
            "family": int(tokens[5]),
            "ip": ip,
            "port": port,
            "retval": int(tokens[8])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected CONNECT trace line: {connect_trace_line}")
        feature_.update({"fd": None, "family": None, "ip": None,
                         "port": None, "retval": None})
        return feature_

    LOG.debug(f"Extracted connect features: {feature_}")
    return feature_


def extract_listen_features(listen_trace_line, endian=None, feature_=None):
    """
    Given a trace line for a listen syscall, extract relevant features:
    socket fd, backlog.

    An example trace line is:
    LISTEN,10:39:03.030411129,143,MKyRatv8,4,1
    This is of format:
    syscall_name,timestamp,process_id,process_name,socket_fd,backlog

    :param listen_trace_line: Trace line for listen syscall
    :type listen_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = listen_trace_line.strip(b"\n").split(b",")

    try:
        feature_.update({
            "fd": int(tokens[4]),
            "backlog": int(tokens[5])
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected LISTEN trace line: {listen_trace_line}")
        feature_.update({"fd": None, "backlog": None})
        return feature_

    LOG.debug(f"Extracted listen features: {feature_}")
    return feature_


def extract_sendto_features(sendto_trace_line, endian=None, feature_=None):
    """
    Given a trace line for sendto syscall, extract relevant features:
    socket fd, buffer, buffer length

    An example trace line is:
    SENDTO,10:39:03.030701375,143,ping,3,<data>,28
    This is of format:
    syscall_name,timestamp,process_id,process_name,socket_fd,data buffer,buffer length

    :param sendto_trace_line: Trace line for sendto syscall
    :type sendto_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = sendto_trace_line.strip(b"\n").split(b",")

    try:
        num_bytes_to_read = int(tokens[6])
        feature_.update({
            "fd": int(tokens[4]),
            # I read 64 bytes by default inside the tracer, so if num_bytes_to_read
            # is less than 64, than I'll show the appropriate number of bytes to
            # the user.
            "buffer": tokens[5][:num_bytes_to_read],
            "size": num_bytes_to_read
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected SENDTO trace line: {sendto_trace_line}")
        feature_.update({"fd": None, "buffer": None, "size": None})
        return feature_

    LOG.debug(f"Extracted sendto features: {feature_}")
    return feature_


def extract_recvfrom_features(recvfrom_trace_line, endian=None, feature_=None):
    """
    Given a trace line for recvfrom syscall, extract relevant features:
    socket fd, buffer, buffer length

    An example trace line is:
    RECVFROM,10:40:03.030701375,143,ping,3,<data>,1024
    This is of format:
    syscall_name,timestamp,process_id,process_name,socket_fd,data buffer,buffer length

    :param recvfrom_trace_line: Trace line for recvfrom syscall
    :type recvfrom_trace_line: bytes
    :param endian: Endian-ness of the sample
    :type endian: str
    :param feature_: Already extracted features: event name, PID, timestamp, process name
    :type feature_: dict
    :return: Additional extracted features
    :rtype: dict
    """
    if feature_ is None:
        feature_ = {}
    tokens = recvfrom_trace_line.strip(b"\n").split(b",")

    try:
        num_bytes_to_read = int(tokens[6])
        feature_.update({
            "fd": int(tokens[4]),
            # I read 64 bytes by default inside the tracer, so if num_bytes_to_read
            # is less than 64, than I'll show the appropriate number of bytes to
            # the user.
            "buffer": tokens[5][:num_bytes_to_read],
            "size": num_bytes_to_read
        })
    except (IndexError, ValueError):
        # Unexpected trace line
        LOG.error(f"Unexpected RECVFROM trace line: {recvfrom_trace_line}")
        feature_.update({"fd": None, "buffer": None, "size": None})
        return feature_

    LOG.debug(f"Extracted recvfrom features: {feature_}")
    return feature_
