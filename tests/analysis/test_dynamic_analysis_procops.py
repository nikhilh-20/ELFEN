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
class DynamicAnalysisProcopsTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "ec399f4c159c07e8f7a89a7da1cc700bc17d8ccd600b7e5a56bd36bb77b622a6"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            False, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
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

    def test_check_procops_trace(self):
        """
        The sandbox dumps process-operations related trace in a file called
        "procops.trace". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "procops.trace")))

    def test_read_procops_trace(self):
        """
        Read the procops.trace file and check that it contains the expected
        operations.
        """
        with open(os.path.join(self.dynamic_analysis_dir, "filename"), "rb") as f:
            sample_randomized_filename = f.read().strip()

        procops_trace = os.path.join(self.dynamic_analysis_dir, "procops.trace")
        procops, _ = read_tracers({procops_trace})
        self.assertGreater(len(procops), 0)

        expected_syscall_traces = {
            # Ignoring expected PID, PPID values in fork, getpid, getppid
            # since there is no guarantee that they'll be the same values
            # in staging environments.
            "fork": [],
            "getpid": [],
            "getppid": [],
            "execve": [(b"ChildProcess", b"/bin/ls", b"-la", b"")],
            "prctl": [
                (b"1", b"15"),
                (b"15", b"ChildProcess")
            ],
        }

        expected_match_counts = {
            "fork": 1,
            "getpid": 2,
            "getppid": 1,
            "execve": len(expected_syscall_traces["execve"]),
            "prctl": len(expected_syscall_traces["prctl"])
        }

        for entry in procops:
            items = entry.split(b",")
            if items[0].lower() == b"fork":
                if items[3] == sample_randomized_filename:
                    expected_match_counts["fork"] -= 1
            elif items[0].lower() == b"getpid":
                if items[3] == sample_randomized_filename:
                    expected_match_counts["getpid"] -= 1
            elif items[0].lower() == b"getppid":
                if items[3] == sample_randomized_filename:
                    expected_match_counts["getppid"] -= 1
            elif items[0].lower() == b"execve":
                match_entry = (items[3], items[4], items[5], items[6])
                if match_entry in expected_syscall_traces["execve"]:
                    expected_match_counts["execve"] -= 1
            elif items[0].lower() == b"prctl":
                match_entry = (items[4], items[5])
                if match_entry in expected_syscall_traces["prctl"]:
                    expected_match_counts["prctl"] -= 1

        for syscall, count in expected_match_counts.items():
            self.assertEqual(count, 0)
