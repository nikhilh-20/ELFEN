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

from analysis.analysis_models.dynamic_analysis import PrctlEvent, ExecveEvent


class Process:
    def __init__(self, dynamic_reports):
        self.dynamic_reports = dynamic_reports
        self.score = 0
        self.err_msg = ""
        self.triggered_detectors = []

    def detect_vim_cmd_execve(self):
        """
        Checks for the execution of various vim-cmd (ESXi-related) invocations
        """
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = ExecveEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            exec_path = obj.exec_path.tobytes()
            if exec_path == b"/usr/bin/vim-cmd":
                arg1 = obj.arg1.tobytes()
                if arg1 == b"hostsvc/autostartmanager/enable_autostart":
                    arg2 = obj.arg2.tobytes()
                    if arg2 == b"0":
                        dict_ = {
                            "file": None,
                            "detector": {
                                "name": type(self).__name__ + f":VimCmdExecve",
                                "score": 30,
                                "author": "Nikhil Hegde <ka1do9>",
                                "mitre_attack": "T1489: Service Stop",
                                "description": "Detects disabling of auto-start of ESXi VMs through vim-cmd binary"
                            }
                        }
                    else:
                        continue
                elif arg1 == b"vmsvc/getallvms":
                    dict_ = {
                        "file": None,
                        "detector": {
                            "name": type(self).__name__ + f":VimCmdExecve",
                            "score": 10,
                            "author": "Nikhil Hegde <ka1do9>",
                            "mitre_attack": "T1018: Remote System Discovery",
                            "description": "Detects listing of ESXi VMs through vim-cmd binary"
                        }
                    }
                elif arg1 == b"vmsvc/power.off":
                    dict_ = {
                        "file": None,
                        "detector": {
                            "name": type(self).__name__ + f":VimCmdExecve",
                            "score": 30,
                            "author": "Nikhil Hegde <ka1do9>",
                            "mitre_attack": "T1529: System Shutdown/Reboot",
                            "description": "Detects powering off of ESXi VM through vim-cmd binary"
                        }
                    }
                elif arg1 == b"vmsvc/snapshot.removeall":
                    dict_ = {
                        "file": None,
                        "detector": {
                            "name": type(self).__name__ + f":VimCmdExecve",
                            "score": 30,
                            "author": "Nikhil Hegde <ka1do9>",
                            "mitre_attack": "T1490: Inhibit System Recovery",
                            "description": "Detects removal of snapshots of ESXi VM through vim-cmd binary"
                        }
                    }
                else:
                    continue

                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_esxcli_execve(self):
        """
        Checks for the execution of various esxcli (ESXi-related) invocations
        """
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = ExecveEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            exec_path = obj.exec_path.tobytes()
            # ELFEN only records two arguments for a binary executed through execve.
            # TODO: This is a technical issue that needs to be improved.
            # An actual esxcli invocation might be: "esxcli vm process kill --type=force --world-id=tWorld ID: 4825233"
            # If we look at the corresponding execve trace, it will show binary path as "/usr/bin/esxcli" and arguments
            # as "vm" and "process" only.
            # So, as a best effort, we will check for invocation of "/bin/sh" and then check for the presence of
            # "esxcli" in its arguments. This might show the full cmdline.

            if exec_path == b"/bin/sh":
                arg2 = obj.arg2.tobytes()
                if arg2.startswith(b"esxcli"):
                    if b"vm process kill" in arg2:
                        dict_ = {
                            "file": None,
                            "detector": {
                                "name": type(self).__name__ + f":EsxcliExecve",
                                "score": 30,
                                "author": "Nikhil Hegde <ka1do9>",
                                "mitre_attack": "T1529: System Shutdown/Reboot",
                                "description": "Detects killing of ESXi VM through esxcli binary"
                            }
                        }
                    else:
                        continue
                else:
                    continue

                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_process_name_change(self):
        """
        Checks for the presence of process name changes. If so, it will
        increase the score.
        """
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = PrctlEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            option = obj.option
            # https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h#L56
            if option == 15:
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":NameChange",
                        "score": 30,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1036: Masquerading",
                        "description": "Detects process name change through prctl()"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def detect_uptime_process_execve(self):
        """
        Checks for the execution of "uptime" command in an ExecveEvent. If so,
        it will increase the score.
        """
        target_cmd = b"uptime"
        kernel_trace = self.dynamic_reports.kernel_trace
        objs = ExecveEvent.objects.filter(kernel_trace=kernel_trace)

        for obj in objs:
            arg1 = obj.arg1.tobytes()
            arg2 = obj.arg2.tobytes()
            if arg1 == target_cmd or arg2 == target_cmd:
                dict_ = {
                    "file": None,
                    "detector": {
                        "name": type(self).__name__ + f":UptimeExecve",
                        "score": 30,
                        "author": "Nikhil Hegde <ka1do9>",
                        "mitre_attack": "T1497: Virtualization/Sandbox Evasion",
                        "description": "Detects \"uptime\" command execution"
                    }
                }
                if dict_ not in self.triggered_detectors:
                    self.triggered_detectors.append(dict_)

    def calc_score(self):
        scores = []
        for entry in self.triggered_detectors:
            detector = entry["detector"]
            s = detector["score"]
            if s:
                scores.append(s)

        self.score = max(scores) if scores else 0

    def detect(self, data):
        self.detect_process_name_change()
        self.detect_uptime_process_execve()
        self.detect_vim_cmd_execve()
        self.detect_esxcli_execve()

        self.calc_score()
