import os
import tlsh

from django.conf import settings
from django.test import TestCase, tag

from analysis.models import SampleMetadata
from analysis.analysis.periodic import hac_t_cluster


class PeriodicAnalysisClusteringTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")

    def test_check_tlsh_clustering(self):
        """
        This test checks that the TLSH-clustering is operating as expected
        """
        sha256_1 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample1_path = os.path.join(self.bin_dir, sha256_1)
        sha256_2 = "102e68c030aa7a57c3cfb554904c335483575998335d14ac8c6d032fd732ab3d"
        sample2_path = os.path.join(self.bin_dir, sha256_2)

        sample1 = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256_1,
            tlsh=tlsh.hash(open(sample1_path, "rb").read()),
            username="test"
        )
        sample2 = SampleMetadata.objects.create(
            md5="99643704df13dc26f3f40cb194f44227",
            sha1="d42858234eaa16631a3a0c85f752a0a7032959b2",
            sha256=sha256_2,
            tlsh=tlsh.hash(open(sample2_path, "rb").read()),
            username="test"
        )
        labels = hac_t_cluster([sample1, sample2])

        # Both samples are similar and should be clustered together
        self.assertEqual(labels[0], labels[1])
