import os
import shutil

from django.conf import settings
from django.test import TestCase, tag

from analysis.models import SampleMetadata
from analysis.analysis.static import apply_feature_extractor
from analysis.analysis.utils.dynamic.dynamic import read_tracers
from analysis.analysis.dynamic import setup_sandbox_files, create_esxcli_files
from analysis.analysis.utils.dynamic.behavior import deploy_qemu, get_image_info


@tag("slow")
class DynamicAnalysisNetopsTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "d69177f28e1b9079053e30dbc67fffdece2439850b4c4c2df53c0af33b6e6125"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            False, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        sample = SampleMetadata.objects.create(
            md5="1d38a6a8a21f482360cc2bb0f6235c08",
            sha1="d0987b7342857806acb904414f9245adf3796e7e",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(cls.bin_dir, sha256))
        arch, endian = features.arch, features.endian
        image_info = get_image_info(arch, endian, False)
        create_esxcli_files(cls.dynamic_analysis_dir)
        deploy_qemu(15, int(exec_time), arch, endian, cls.dynamic_analysis_dir,
                    False, image_info)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dynamic_analysis_dir)

    def test_check_sample_filename(self):
        """
        The sandbox randomizes the main sample filename before execution and
        stores the randomized name in a file called "filename". Check for its
        existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "filename")))

    def test_check_netops_trace(self):
        """
        The sandbox dumps network-operations related trace in a file called
        "netops.trace". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "netops.trace")))

    def test_read_netops_trace(self):
        """
        Read the netops.trace file and check that it contains the expected
        operations.
        """
        netops_trace = os.path.join(self.dynamic_analysis_dir, "netops.trace")
        netops, _ = read_tracers({netops_trace})
        self.assertGreater(len(netops), 0)

        expected_syscall_traces = {
            "socket": [(b"2", b"1", b"0")],
            "setsockopt": [(b"1", b"2", b"\\x01", b"4")],
            "bind": [(b"2", b"0", b"36895")],
            "connect": [(b"2", b"16777343", b"36895")],
            "listen": [b"5"],
        }

        expected_match_counts = {
            "socket": len(expected_syscall_traces["socket"]),
            "setsockopt": len(expected_syscall_traces["setsockopt"]),
            "bind": len(expected_syscall_traces["bind"]),
            "connect": len(expected_syscall_traces["connect"]),
            "listen": len(expected_syscall_traces["listen"])
        }

        for entry in netops:
            items = entry.split(b",")
            if items[0].lower() == b"socket":
                match_entry = (items[4], items[5], items[6])
                if match_entry in expected_syscall_traces["socket"]:
                    expected_match_counts["socket"] -= 1
            elif items[0].lower() == b"setsockopt":
                match_entry = (items[5], items[6], items[7], items[8])
                if match_entry in expected_syscall_traces["setsockopt"]:
                    expected_match_counts["setsockopt"] -= 1
            elif items[0].lower() == b"bind":
                match_entry = (items[5], items[6], items[7])
                if match_entry in expected_syscall_traces["bind"]:
                    expected_match_counts["bind"] -= 1
            elif items[0].lower() == b"connect":
                match_entry = (items[5], items[6], items[7])
                if match_entry in expected_syscall_traces["connect"]:
                    expected_match_counts["connect"] -= 1
            elif items[0].lower() == b"listen":
                if items[5] in expected_syscall_traces["listen"]:
                    expected_match_counts["listen"] -= 1

        for syscall, count in expected_match_counts.items():
            self.assertEqual(count, 0)
