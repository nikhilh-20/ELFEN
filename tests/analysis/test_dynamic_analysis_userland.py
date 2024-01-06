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
class DynamicAnalysisUserlandTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "e4d10b0142721c42d55f2bfa975003981d20058eccf577939180aa5f0fa0c4dd"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            True, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        sample = SampleMetadata.objects.create(
            md5="50bc4e49486bc561fb0d9d760044c780",
            sha1="e65f4a6a01b2328f03e8be941b3e46e3eaee0d1b",
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

    def test_check_userland_trace(self):
        """
        The sandbox dumps libc-operations related trace in a file called
        "userland.trace". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "userland.trace")))

    def test_read_userland_trace(self):
        """
        Read the userland.trace file and check that it contains the expected
        operations.
        """
        userland_trace = os.path.join(self.dynamic_analysis_dir, "userland.trace")
        _, userland = read_tracers({userland_trace})
        self.assertGreater(len(userland), 0)

        expected_libccall_traces = {
            "strcmp": [(b"hello", b"world")],
            "strncmp": [(b"apple", b"appetizer", b"5")],
            "strstr": [(b"Hello", b" World! This is a test string.", b"World")],
            "strcpy": [b"Copy this!"],
            "strncpy": [(b"Copy this!", b"9")]
        }

        expected_match_counts = {
            "strcmp": len(expected_libccall_traces["strcmp"]),
            "strncmp": len(expected_libccall_traces["strncmp"]),
            "strstr": len(expected_libccall_traces["strstr"]),
            "strcpy": len(expected_libccall_traces["strcpy"]),
            "strncpy": len(expected_libccall_traces["strncpy"]),
        }

        for entry in userland:
            items = entry.split(b",")
            if items[0].lower() == b"strcmp":
                match_entry = (items[3], items[4])
                if match_entry in expected_libccall_traces["strcmp"]:
                    expected_match_counts["strcmp"] -= 1
            elif items[0].lower() == b"strncmp":
                match_entry = (items[3], items[4], items[5])
                if match_entry in expected_libccall_traces["strncmp"]:
                    expected_match_counts["strncmp"] -= 1
            elif items[0].lower() == b"strstr":
                match_entry = (items[3], items[4], items[5])
                if match_entry in expected_libccall_traces["strstr"]:
                    expected_match_counts["strstr"] -= 1
            elif items[0].lower() == b"strcpy":
                if items[3] in expected_libccall_traces["strcpy"]:
                    expected_match_counts["strcpy"] -= 1
            elif items[0].lower() == b"strncpy":
                match_entry = (items[3], items[4])
                if match_entry in expected_libccall_traces["strncpy"]:
                    expected_match_counts["strncpy"] -= 1

        for syscall, count in expected_match_counts.items():
            self.assertEqual(count, 0)
