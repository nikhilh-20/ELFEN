import os
import signal
import shutil
import subprocess
from django.conf import settings
from django.test import TestCase

from analysis.models import SampleMetadata
from analysis.analysis.static import apply_feature_extractor
from analysis.analysis.dynamic import create_esxcli_files
from analysis.analysis.utils.dynamic.behavior import get_qemu_cmd, get_arch_image_7z,\
                                                     get_image_info, get_arch_endian_from_machine_name


class SandboxDeploymentTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.bin_dir = os.path.join(settings.BASE_DIR, "tests", "analysis",
                                   "files", "binaries")
        cls.dynamic_analysis_dir = "/tmp/dynamic_analysis_dir"

    def setUp(self):
        os.mkdir(self.dynamic_analysis_dir)

    def tearDown(self):
        shutil.rmtree(self.dynamic_analysis_dir, ignore_errors=True)

    def test_check_user_choice_machine_image_retrieval(self):
        """
        Check if user choice's machine image is retrieved.
        """
        machine = "buildroot_armv5_32bit"
        arch, endian = get_arch_endian_from_machine_name(machine)
        image, _ = get_arch_image_7z(arch, endian, True)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "arm", "image_net.7z"))

    def test_check_correct_image_retrieval_no_internet(self):
        """
        Check if correct buildroot image is retrieved for a given binary's
        target architecture when no internet access is enabled.
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "amd64")
        image, _ = get_arch_image_7z(arch, endian, False)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "x8664", "image.7z"))

        sha256 = "f8f40609bf7440a468864b63b1687409d28113abd76302108360bcc7d80567d9"
        sample = SampleMetadata.objects.create(
            md5="88ced990fcbdd11e4f104f5e1a69bba9",
            sha1="5939d2985cc689b220af91b6b733cf32efddb69a",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "arm")
        self.assertEqual(endian, "le")
        image, _ = get_arch_image_7z(arch, endian, False)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "arm", "image.7z"))

        sha256 = "f188329c9f1118f923c80a8a7bba2013c0f9f4016e807504e3d8124b27490700"
        sample = SampleMetadata.objects.create(
            md5="65a87a8e01573d55ee4dd45d8fe0e36f",
            sha1="d419622236646c38c9abfd7fb3a1429b2b9eaf7b",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "mips")
        self.assertEqual(endian, "be")
        image, _ = get_arch_image_7z(arch, endian, False)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "mips", "image.7z"))

        sha256 = "580a0ba6c9615fa2a211ac93692f8b7ee79de6871f391d84fbd46fec59c4fec7"
        sample = SampleMetadata.objects.create(
            md5="4b76f9f1be9b70ca1bdf17299f563f5b",
            sha1="66f8063d3acf1b63c28d060612c5301a235ae0ac",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "mips")
        self.assertEqual(endian, "le")
        image, _ = get_arch_image_7z(arch, endian, False)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "mipsel", "image.7z"))

        sha256 = "572ded5ac526803942809cd44ecaafb48081cda422093f53514ad3d9126d8d0e"
        sample = SampleMetadata.objects.create(
            md5="75cd00738db89d83f4e29d62563eb124",
            sha1="8d3eaffac0354e4bbc7986cc6310e5838bdca297",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "ppc")
        image, _ = get_arch_image_7z(arch, endian, False)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "ppc", "image.7z"))

    def test_check_correct_image_retrieval_internet(self):
        """
        Check if correct buildroot image is retrieved for a given binary's
        target architecture when internet access is enabled.
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "amd64")
        image, _ = get_arch_image_7z(arch, endian, True)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "x8664", "image_net.7z"))

        sha256 = "f8f40609bf7440a468864b63b1687409d28113abd76302108360bcc7d80567d9"
        sample = SampleMetadata.objects.create(
            md5="88ced990fcbdd11e4f104f5e1a69bba9",
            sha1="5939d2985cc689b220af91b6b733cf32efddb69a",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "arm")
        self.assertEqual(endian, "le")
        image, _ = get_arch_image_7z(arch, endian, True)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "arm", "image_net.7z"))

        sha256 = "f188329c9f1118f923c80a8a7bba2013c0f9f4016e807504e3d8124b27490700"
        sample = SampleMetadata.objects.create(
            md5="65a87a8e01573d55ee4dd45d8fe0e36f",
            sha1="d419622236646c38c9abfd7fb3a1429b2b9eaf7b",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "mips")
        self.assertEqual(endian, "be")
        image, _ = get_arch_image_7z(arch, endian, True)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "mips", "image_net.7z"))

        sha256 = "580a0ba6c9615fa2a211ac93692f8b7ee79de6871f391d84fbd46fec59c4fec7"
        sample = SampleMetadata.objects.create(
            md5="4b76f9f1be9b70ca1bdf17299f563f5b",
            sha1="66f8063d3acf1b63c28d060612c5301a235ae0ac",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "mips")
        self.assertEqual(endian, "le")
        image, _ = get_arch_image_7z(arch, endian, True)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "mipsel", "image_net.7z"))

        sha256 = "572ded5ac526803942809cd44ecaafb48081cda422093f53514ad3d9126d8d0e"
        sample = SampleMetadata.objects.create(
            md5="75cd00738db89d83f4e29d62563eb124",
            sha1="8d3eaffac0354e4bbc7986cc6310e5838bdca297",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        arch, endian = features.arch.lower(), features.endian.lower()
        self.assertEqual(arch, "ppc")
        image, _ = get_arch_image_7z(arch, endian, True)
        self.assertEqual(image, os.path.join(settings.BASE_DIR, "rsrc",
                                             "ELFEN_images", "images",
                                             "ppc", "image_net.7z"))

    def test_check_esxcli_files_creation(self):
        """
        Check if esxcli files are created as expected.
        """
        status = create_esxcli_files(self.dynamic_analysis_dir)
        self.assertTrue(status)

        req_files = ["esxcli", "vm_name", "volume_id"]
        for item in req_files:
            self.assertTrue(os.path.isfile(os.path.join(self.dynamic_analysis_dir, item)))

        extensions = [".vmx", ".vmxf", ".vmdk", ".nvram"]
        for item in os.listdir(self.dynamic_analysis_dir):
            if not item or item in req_files:
                continue
            _, file_extension = os.path.splitext(item)
            self.assertIn(file_extension, extensions)

    def test_check_qemu_arm_cmdline(self):
        """
        Checks if the retrieved QEMU command line is correct for ARM binaries
        when internet access is enabled. It requires a slightly modified
        command line compared to other architectures.
        """
        sha256 = "f8f40609bf7440a468864b63b1687409d28113abd76302108360bcc7d80567d9"
        sample = SampleMetadata.objects.create(
            md5="88ced990fcbdd11e4f104f5e1a69bba9",
            sha1="5939d2985cc689b220af91b6b733cf32efddb69a",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        image_info = get_image_info(features.arch, features.endian, True)
        qemu_cmd = get_qemu_cmd(features.arch, features.endian,
                                self.dynamic_analysis_dir, True, image_info)
        self.assertIn("-netdev user,id=unet -device driver=virtio-net,netdev=unet", qemu_cmd,
                      "Correct QEMU command line not retrieved for ARM.")

    def test_check_qemu_deployment(self):
        """
        Check if QEMU was deployed for a given buildroot image.
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        image_info = get_image_info(features.arch, features.endian, False)
        qemu_cmd = get_qemu_cmd(features.arch, features.endian,
                                self.dynamic_analysis_dir, False, image_info)
        try:
            proc = subprocess.Popen(qemu_cmd, shell=True, preexec_fn=os.setsid)
            self.assertIsNotNone(proc.pid)
            os.killpg(proc.pid, signal.SIGTERM)
        except subprocess.CalledProcessError:
            self.fail("QEMU sandbox for x86-64 failed to start")

        sha256 = "f8f40609bf7440a468864b63b1687409d28113abd76302108360bcc7d80567d9"
        sample = SampleMetadata.objects.create(
            md5="88ced990fcbdd11e4f104f5e1a69bba9",
            sha1="5939d2985cc689b220af91b6b733cf32efddb69a",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        image_info = get_image_info(features.arch, features.endian, False)
        qemu_cmd = get_qemu_cmd(features.arch, features.endian,
                                self.dynamic_analysis_dir, False, image_info)
        try:
            proc = subprocess.Popen(qemu_cmd, shell=True, preexec_fn=os.setsid)
            self.assertIsNotNone(proc.pid)
            os.killpg(proc.pid, signal.SIGTERM)
        except subprocess.CalledProcessError:
            self.fail("QEMU sandbox for ARM failed to start")

        sha256 = "f188329c9f1118f923c80a8a7bba2013c0f9f4016e807504e3d8124b27490700"
        sample = SampleMetadata.objects.create(
            md5="65a87a8e01573d55ee4dd45d8fe0e36f",
            sha1="d419622236646c38c9abfd7fb3a1429b2b9eaf7b",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        image_info = get_image_info(features.arch, features.endian, False)
        qemu_cmd = get_qemu_cmd(features.arch, features.endian,
                                self.dynamic_analysis_dir, False, image_info)
        try:
            proc = subprocess.Popen(qemu_cmd, shell=True, preexec_fn=os.setsid)
            self.assertIsNotNone(proc.pid)
            os.killpg(proc.pid, signal.SIGTERM)
        except subprocess.CalledProcessError:
            self.fail("QEMU sandbox for MIPS failed to start")

        sha256 = "580a0ba6c9615fa2a211ac93692f8b7ee79de6871f391d84fbd46fec59c4fec7"
        sample = SampleMetadata.objects.create(
            md5="4b76f9f1be9b70ca1bdf17299f563f5b",
            sha1="66f8063d3acf1b63c28d060612c5301a235ae0ac",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        image_info = get_image_info(features.arch, features.endian, False)
        qemu_cmd = get_qemu_cmd(features.arch, features.endian,
                                self.dynamic_analysis_dir, False, image_info)
        try:
            proc = subprocess.Popen(qemu_cmd, shell=True, preexec_fn=os.setsid)
            self.assertIsNotNone(proc.pid)
            os.killpg(proc.pid, signal.SIGTERM)
        except subprocess.CalledProcessError:
            self.fail("QEMU sandbox for MIPSel failed to start")

        sha256 = "572ded5ac526803942809cd44ecaafb48081cda422093f53514ad3d9126d8d0e"
        sample = SampleMetadata.objects.create(
            md5="75cd00738db89d83f4e29d62563eb124",
            sha1="8d3eaffac0354e4bbc7986cc6310e5838bdca297",
            sha256=sha256,
            username="test"
        )
        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        image_info = get_image_info(features.arch, features.endian, False)
        qemu_cmd = get_qemu_cmd(features.arch, features.endian,
                                self.dynamic_analysis_dir, False, image_info)
        try:
            proc = subprocess.Popen(qemu_cmd, shell=True, preexec_fn=os.setsid)
            self.assertIsNotNone(proc.pid)
            os.killpg(proc.pid, signal.SIGTERM)
        except subprocess.CalledProcessError:
            self.fail("QEMU sandbox for PowerPC failed to start")