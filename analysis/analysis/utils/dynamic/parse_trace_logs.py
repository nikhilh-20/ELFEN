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
from analysis.analysis.utils.dynamic.extract_event_features import *

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)

PLY_TRACERS = {
    "fileops": FILEOPS_EVENTS,
    "procops": PROCOPS_EVENTS,
    "fcntlops": FCNTLOPS_EVENTS,
    "netops": NETOPS_EVENTS,
    "netcomms": NETCOMMS_EVENTS,
}

USERLAND_TRACERS = {
    "str": STR_USERLAND_EVENTS
}


def parse_userland_tracer_log(log_content):
    """
    Parse userland tracer log content.

    :param log_content: Content of tracer log
    :type log_content: str
    :return: Parsed tracer logs
    :rtype: list of bytes
    """
    LOG.debug(f"Parsing userland tracer log content")
    tracings = []
    tracings_ = []
    log_content = log_content.encode("unicode_escape")

    events = set()
    for _, v in USERLAND_TRACERS.items():
        events = events.union(v)
    LOG.debug(f"Events traced in userland: {events}")

    pattern = b"(" + b"|".join([re.escape(event) for event in events]) + b")"
    segments = re.split(pattern, log_content)
    if segments[0] == b"":
        segments = segments[1:]

    for s in segments:
        if s in events:
            tracings_.append(s)
            continue

        tracings_[-1] += s

    # Trace of certain system binaries are not relevant
    for t in tracings_:
        if b"\\x00" in t:
            # Came across huge sequences of NULL bytes. Not sure why they're there.
            # Likely there's a bug in the userland tracer SO library.
            # Corrupted trace line
            continue
        found = False
        for b in USERLAND_IGNORE_BINARIES:
            procname = t.split(b",")[2]
            if procname == b:
                found = True

        if not found:
            tracings.append(t)

    # Skip the "\\n" character at the end of each trace line
    tracings = [t[:-2] if t.endswith(b"\\n") else t for t in tracings]

    LOG.debug(f"Parsing userland traces complete")
    return tracings


def parse_ply_tracer_log(log_content, tracer):
    """
    Parse ply tracer logs.

    :param log_content: Content of tracer log
    :type log_content: str
    :param tracer: Tracer name
    :type tracer: str
    :return: Parsed logs
    :rtype: list of bytes
    """
    LOG.debug(f"Parsing ply tracer log content")
    tracings = []
    tracings_ = []
    log_content = log_content.encode("unicode_escape")

    events = PLY_TRACERS[tracer]
    LOG.debug(f"Events traced in ply: {events}")

    # pattern = b"(" + b"|".join([re.escape(event) for event in events.keys()]) + b")"
    pattern = b"(" + b"|".join([event + b"," for event in events.keys()]) + b")"
    segments = re.split(pattern, log_content)

    if segments[0] == b"":
        segments = segments[1:]

    for s in segments:
        if get_ply_kallsyms_str() in s or get_ply_events_lost_substr() in s:
            LOG.debug(f"Irrelevant trace line: {s} removed")
            continue

        if (get_tracer_dir() in s or get_memdump_dir() in s or
                get_elfen_lib() in s or get_memdump_reader() in s):
            # The last element in tracings would have been an OPEN syscall that
            # gets a handle to the userland.trace file, for example.
            # We need to remove that syscall from the tracings list.
            LOG.debug(f"Irrelevant trace line: {s} removed")
            tracings_.pop()
            continue

        # s is of the form b"READ," but events is of the form b"READ"
        if s.split(b",")[0] in events:
            tracings_.append(s)
            continue

        # When ply exits, it prints leftover map values to the log.
        # Those should be filtered out. With the condition below, it is
        # required that map variables in a map tracer contain the substring
        # "_map". For example: read_mapN, kill_map, etc. See existing ply
        # tracers for examples.
        if b"\\n\\n" in s and b"_map" in s:
            LOG.debug(f"Ignoring leftover map values from trace line: {s}")
            s = s[:s.index(b"\\n\\n")]

        tracings_[-1] += s

    # Skip the "\\n" character at the end of each trace line
    tracings_ = [t[:-2] if t.endswith(b"\\n") else t for t in tracings_]

    # Ensure integrity of each trace line. Corruptions may exist
    LOG.debug("Ensuring integrity of trace lines by checking components "
              "in each event")
    for t in tracings_:
        syscall = t.split(b",")[0]
        num_components = events[syscall]
        if len(t.split(b",")) not in num_components:
            # Corrupted trace line. Skip it.
            continue
        tracings.append(t)

    LOG.debug(f"Parsing ply traces complete")
    return tracings
