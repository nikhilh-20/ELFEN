import os
import shutil

from django.conf import settings
from django.test import TestCase, tag

from analysis.models import SampleMetadata
from analysis.analysis.static import apply_feature_extractor
from analysis.analysis.network import perform_pcap_analysis
from analysis.reporting.utils.get_network_reports_values import get_dns_analysis_values
from analysis.analysis.dynamic import setup_sandbox_files, create_esxi_files
from analysis.analysis.utils.dynamic.behavior import deploy_qemu, get_image_info


@tag("slow")
class NetworkAnalysisPcapAnalysisTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"
        os.mkdir(cls.dynamic_analysis_dir)

        sha256 = "65c0f964cade2e4850619343662d2c578a3c188ffdd5f9bbbfead9d97d11f9a7"
        sample_path = os.path.join(cls.bin_dir, sha256)
        exec_time = "10"
        # Setting task_reports and dynamic_analysis_report to None
        # They're used within setup_sandbox_files() if an exception is raised
        # but no such exception is expected
        setup_sandbox_files(sample_path, [], "", exec_time,
                            False, "/tmp", cls.dynamic_analysis_dir,
                            None, None)

        cls.sample = SampleMetadata.objects.create(
            md5="08209e4b8ce6f9b7e1c2b3a6cee26e45",
            sha1="9f0eb6f920337d9ca4354094563049d775701e92",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(cls.sample, os.path.join(cls.bin_dir, sha256))
        arch, endian = features.arch, features.endian
        image_info = get_image_info(arch, endian, True)
        create_esxi_files(cls.dynamic_analysis_dir)
        deploy_qemu(15, int(exec_time), arch, endian, cls.dynamic_analysis_dir,
                    True, image_info)

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

    def test_check_pcap_capture(self):
        """
        The sandbox dumps the captured pcap in a file called
        "capture.pcap". Check for its existence.
        """
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir,
                                                    "capture.pcap")))

    def test_dns_analysis(self):
        """
        Parse capture.pcap and check that it contains the expected data. This
        test is particularly fickle because it relies on network traffic from
        an uncontrolled source (the server) which may change at any time.
        """
        pcap_file = os.path.join(self.dynamic_analysis_dir, "capture.pcap")
        pcap_analysis_obj = perform_pcap_analysis(pcap_file, self.sample)
        dns_info, _ = get_dns_analysis_values(self.sample, pcap_analysis_obj)

        for txid in dns_info:
            query_entry = dns_info[txid]["query"]
            # Assert query entries
            self.assertEqual(len(query_entry["qd"]), 1)
            self.assertEqual(len(query_entry["ar"]), 0)
            self.assertEqual(query_entry["qd"][0]["query_domain"], "google.com")
            self.assertEqual(query_entry["qd"][0]["query_type"], "A")
            self.assertEqual(query_entry["qd"][0]["query_class"], "IN")

            response_entry = dns_info[txid]["response"]
            # Assert response entries
            self.assertGreater(response_entry["ancount"], 0)
            self.assertEqual(response_entry["an"][0]["response_type"], "A")
            self.assertEqual(response_entry["an"][0]["response_class"], "IN")
