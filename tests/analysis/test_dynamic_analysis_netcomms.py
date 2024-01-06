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
class DynamicAnalysisNetcommsTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "c563067392e6ff7ee1a668ecb695d9f449bb7c4c60693d4505be87297d9118ce"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            False, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        sample = SampleMetadata.objects.create(
            md5="7368409c92bb42b4b9d1d37aafb43a87",
            sha1="bb3205ca3f96f1b7cfeeb016191f68bbd70db458",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(cls.bin_dir, sha256))
        arch, endian = features.arch, features.endian
        image_info = get_image_info(arch, endian, True)
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

    def test_check_netcomms_trace(self):
        """
        The sandbox dumps network-communications related trace in a file called
        "netcomms.trace". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "netcomms.trace")))

    def test_read_netcomms_trace(self):
        """
        Read the netcomms.trace file and check that it contains the expected
        operations.
        """
        netcomms_trace = os.path.join(self.dynamic_analysis_dir, "netcomms.trace")
        netcomms, _ = read_tracers({netcomms_trace})
        self.assertGreater(len(netcomms), 0)

        expected_syscall_traces = {
            "sendto": [(b"3", b"\\x04\\xd2\\xff\\xff", b"27")],
            "recvfrom": [(b"3", b"\\x04\\xd2\\xff\\xff", b"1023")]
        }

        expected_match_counts = {
            "sendto": len(expected_syscall_traces["sendto"]),
            "recvfrom": len(expected_syscall_traces["recvfrom"])
        }

        for entry in netcomms:
            items = entry.split(b",")
            if items[0].lower() == b"sendto":
                match_entry = (items[4], items[5], items[6])
                if match_entry in expected_syscall_traces["sendto"]:
                    expected_match_counts["sendto"] -= 1
            elif items[0].lower() == b"recvfrom":
                match_entry = (items[4], items[5], items[6])
                if match_entry in expected_syscall_traces["recvfrom"]:
                    expected_match_counts["recvfrom"] -= 1

        for syscall, count in expected_match_counts.items():
            self.assertEqual(count, 0)
