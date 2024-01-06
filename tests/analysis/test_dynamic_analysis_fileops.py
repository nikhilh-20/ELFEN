import os
import shutil

from django.conf import settings
from django.test import TestCase, tag

from analysis.models import SampleMetadata
from analysis.analysis.static import apply_feature_extractor
from analysis.analysis.utils.dynamic.dynamic import read_tracers
from analysis.analysis.dynamic import setup_sandbox_files, create_esxi_files
from analysis.analysis.utils.dynamic.behavior import deploy_qemu, get_image_info


@tag("slow")
class DynamicAnalysisFileopsTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "870dfc01d8c1008f7ae2cf7d8fb9b757f8e7e2710ce575b9308692a197aaeef7"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            False, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        sample = SampleMetadata.objects.create(
            md5="dea69fddc6abfc8cde235c5aba220b39",
            sha1="5732fe9fc4738a7f783efcbe3c5d3d1a410553cc",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(cls.bin_dir, sha256))
        arch, endian = features.arch, features.endian
        image_info = get_image_info(arch, endian, False)
        create_esxi_files(cls.dynamic_analysis_dir)
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

    def test_check_fileops_trace(self):
        """
        The sandbox dumps file-operations related trace in a file called
        "fileops.trace". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "fileops.trace")))

    def test_read_fileops_trace(self):
        """
        Read the fileops.trace file and check that it contains the expected file
        operations.
        """
        fileops_trace = os.path.join(self.dynamic_analysis_dir, "fileops.trace")
        fileops, _ = read_tracers({fileops_trace})
        self.assertGreater(len(fileops), 0)

        expected_syscall_traces = {
            "open": [
                (b"input.txt", b"32768"),
                (b"target.txt", b"33345")
            ],
            "read": [(b"This is input content", b"64")],
            "write": [
                (b"This is input content", b"21"),
                (b"This is input content", b"21")
            ],
            "rename": [(b"input.txt", b"rename_input.txt")],
            "readlink": [(b"testlnk", b"/usr/lib/ld-linux.so.2", b"22")],
            "unlink": [b"testlnk"]
        }

        expected_match_counts = {
            "open": len(expected_syscall_traces["open"]),
            "read": len(expected_syscall_traces["read"]),
            "write": len(expected_syscall_traces["write"]),
            "rename": len(expected_syscall_traces["rename"]),
            "readlink": len(expected_syscall_traces["readlink"]),
            "unlink": len(expected_syscall_traces["unlink"])
        }

        for entry in fileops:
            items = entry.split(b",")
            if items[0].lower() == b"open":
                match_entry = (items[4], items[5])
                if match_entry in expected_syscall_traces["open"]:
                    expected_match_counts["open"] -= 1
            elif items[0].lower() == b"read":
                match_entry = (items[5], items[6])
                if match_entry in expected_syscall_traces["read"]:
                    expected_match_counts["read"] -= 1
            elif items[0].lower() == b"write":
                match_entry = (items[5], items[6])
                if match_entry in expected_syscall_traces["write"]:
                    expected_match_counts["write"] -= 1
            elif items[0].lower() == b"rename":
                match_entry = (items[4], items[5])
                if match_entry in expected_syscall_traces["rename"]:
                    expected_match_counts["rename"] -= 1
            elif items[0].lower() == b"readlink":
                match_entry = (items[4], items[5], items[6])
                if match_entry in expected_syscall_traces["readlink"]:
                    expected_match_counts["readlink"] -= 1
            elif items[0].lower() == b"unlink":
                if items[4] in expected_syscall_traces["unlink"]:
                    expected_match_counts["unlink"] -= 1

        for syscall, count in expected_match_counts.items():
            self.assertEqual(count, 0)
