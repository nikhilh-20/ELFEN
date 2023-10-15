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
class DynamicAnalysisFcntlopsTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "283bc45807be383ab51b7100c4c90d989a11c5e882488d033a73ccddf3c34a76"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            False, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        sample = SampleMetadata.objects.create(
            md5="1a253d328d0d0f36d0efd7ad4e022ca9",
            sha1="22bd7f22a400d8cac7ed0ee0b40c0949c32cd4f8",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(cls.bin_dir, sha256))
        arch, endian = features.arch, features.endian
        image_info = get_image_info(arch, endian)
        create_esxcli_files(cls.dynamic_analysis_dir)
        deploy_qemu(15, int(exec_time), arch, endian, cls.dynamic_analysis_dir,
                    image_info)

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

    def test_check_fcntlops_trace(self):
        """
        The sandbox dumps fcntl-operations related trace in a file called
        "fcntlops.trace". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "fcntlops.trace")))

    def test_read_fcntlops_trace(self):
        """
        Read the fcntlops.trace file and check that it contains the expected
        operations.
        """
        fcntlops_trace = os.path.join(self.dynamic_analysis_dir, "fcntlops.trace")
        fcntlops, _ = read_tracers({fcntlops_trace})
        self.assertGreater(len(fcntlops), 0)

        expected_syscall_traces = {
            "fcntl": [
                (b"3", b"0", b"0"),
                (b"3", b"0", b"11")
            ],
        }

        expected_match_counts = {
            "fcntl": len(expected_syscall_traces["fcntl"])
        }

        for entry in fcntlops:
            items = entry.split(b",")
            if items[0].lower() == b"fcntl":
                match_entry = (items[4], items[5], items[6])
                if match_entry in expected_syscall_traces["fcntl"]:
                    expected_match_counts["fcntl"] -= 1

        for syscall, count in expected_match_counts.items():
            self.assertEqual(count, 0)
