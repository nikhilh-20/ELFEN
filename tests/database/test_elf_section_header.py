import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import ELFSectionHeader
from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class ELFSectionHeaderTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        test_string = b'This is a test'
        cls.md5 = hashlib.md5(test_string).hexdigest()
        cls.sha1 = hashlib.sha1(test_string).hexdigest()
        cls.sha256 = hashlib.sha256(test_string).hexdigest()
        cls.sample = SampleMetadata.objects.create(
            md5=cls.md5,
            sha1=cls.sha1,
            sha256=cls.sha256,
        )
        ELFSectionHeader.objects.create(
            sample=cls.sample,
            sh_name=[0, 27],
            sh_name_str=[b'', b'.interp'],
            sh_type=["SHT_NULL", "SHT_PROGBITS"],
            sh_flags=[0, 2],
            sh_addr=[0, 736],
            sh_offset=[0, 736],
            sh_size=[0, 28],
            sh_link=[0, 1],
            sh_info=[0, 0],
            sh_addralign=[0, 0],
            sh_entsize=[0, 1]
        )

    def test_elfsectionheader_update(self):
        """
        This test updates an entry in the ELFSectionHeader table.
        """
        shdr = ELFSectionHeader.objects.get(sample=self.sample)

        updated_sh_type = ["SHT_NULL", "SHT_NOTE"]
        shdr.sh_type = updated_sh_type
        shdr.save()

        shdr = ELFSectionHeader.objects.get(sample=self.sample)
        self.assertEqual(shdr.sh_type, updated_sh_type)

    def test_elfsectionheader_delete(self):
        """
        This test deletes an entry in the ELFSectionHeader table.
        """
        shdr = ELFSectionHeader.objects.get(sample=self.sample)
        shdr.delete()

        try:
            ELFSectionHeader.objects.get(sample=self.sample)
            self.fail('ELFHeader object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_elfsectionheader_onetoone_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the ELFSectionHeader
        object can be deleted. It should not be, since there is a OneToOne constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)

        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass

    def test_elfsectionheader_duplicate(self):
        """
        If a sample is analyzed twice, their ELFSectionHeader entries should still be
        the same, i.e., if two ELFSectionHeader objects are created for the same sample
        object, it should result in django.db.utils.IntegrityError exception. This
        is because ELFSectionHeader.sample is a OneToOneField.
        """
        try:
            ELFSectionHeader.objects.create(
                sample=self.sample,
                sh_name=[0, 27],
                sh_name_str=[b'', b'.interp'],
                sh_type=["SHT_NULL", "SHT_PROGBITS"],
                sh_flags=[0, 2],
                sh_addr=[0, 736],
                sh_offset=[0, 736],
                sh_size=[0, 28],
                sh_link=[0, 1],
                sh_info=[0, 0],
                sh_addralign=[0, 0],
                sh_entsize=[0, 1]
            )
            self.fail('Duplicate ELFSectionHeader entry should not have been created in DB')
        except IntegrityError:
            pass
