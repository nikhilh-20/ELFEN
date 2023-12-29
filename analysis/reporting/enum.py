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

from analysis.analysis_models.dynamic_analysis import *


class StaticBackends:
    ELFHEADER = "elfheader"
    ELFPROGHEADER = "elfprogheader"
    ELFSECTIONHEADER = "elfsectionheader"
    SAMPLEFEATURES = "samplefeatures"
    CAPA = "capa"
    STATICANTIANALYSIS = "staticantianalysis"
    STATICANTIANTIANALYSIS = "staticantiantianalysis"
    STRINGS = "strings"
    SIMILARSAMPLES = "similarsamples"


class DynamicBackends:
    MEMSTRINGS = "memstrings"
    FILEOPS = "fileops"
    PROCOPS = "procops"
    NETOPS = "netops"
    USERLAND = "userland"
    DROPPEDFILES = "droppedfiles"
    C2CONFIG = "c2config"


class NetworkBackends:
    PCAPANALYSIS = "pcapanalysis"


class DetectionBackends:
    BEHAVIORALDETECTION = "behavioraldetection"
    STATICDETECTION = "staticdetection"


FilesystemEvents = {
    ReadEvent: {
        "args": ["fd", "buffer", "size"],
        "ret": None
    },
    ReadlinkEvent: {
        "args": ["file_path", "buffer"],
        "ret": "retval"
    },
    UnlinkEvent: {
        "args": ["file_path"],
        "ret": None
    },
    WriteEvent: {
        "args": ["fd", "buffer", "size"],
        "ret": None
    },
    OpenEvent: {
        "args": ["file_path", "flags"],
        "ret": "fd"
    },
    RenameEvent: {
        "args": ["oldfile_path", "newfile_path"],
        "ret": None
    },
    FcntlEvent: {
        "args": ["fd", "cmd", "arg"],
        "ret": None
    }
}

ProcessEvents = {
    ForkEvent: {
        "args": [],
        "ret": "retval"
    },
    PrctlEvent: {
        "args": ["option", "arg2", "arg3", "arg4", "arg5"],
        "ret": None
    },
    GetPidEvent: {
        "args": [],
        "ret": "retval"
    },
    GetPPidEvent: {
        "args": [],
        "ret": "retval"
    },
    ExecveEvent: {
        "args": ["exec_path", "arg1", "arg2"],
        "ret": None
    },
}

NetworkEvents = {
    SocketEvent: {
        "args": ["domain", "type", "protocol"],
        "ret": "fd"
    },
    SetSockOptEvent: {
        "args": ["fd", "level", "option_name", "option_value", "option_len"],
        "ret": None
    },
    BindEvent: {
        "args": ["fd", "family", "ip", "port"],
        "ret": "retval"
    },
    ConnectEvent: {
        "args": ["fd", "family", "ip", "port"],
        "ret": "retval"
    },
    ListenEvent: {
        "args": ["fd", "backlog"],
        "ret": None
    },
    SendToEvent: {
        "args": ["fd", "buffer", "size"],
        "ret": None
    },
    RecvFromEvent: {
        "args": ["fd", "buffer", "size"],
        "ret": None
    }

}

UserlandEvents = {
    StrcmpEvent: {
        "args": ["str1", "str2"],
    },
    StrncmpEvent: {
        "args": ["str1", "str2", "len"],
    },
    StrstrEvent: {
        "args": ["haystack", "needle"],
    },
    StrcpyEvent: {
        "args": ["src"],
    },
    StrncpyEvent: {
        "args": ["src", "len"],
    },
}
