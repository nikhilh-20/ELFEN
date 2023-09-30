import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import ELFProgramHeader
from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class ELFProgramHeaderTestCase(TestCase):
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

    def test_elfprogramheader_create(self):
        """
        This test creates an entry in the ELFProgramHeader table.
        """
        ELFProgramHeader.objects.create(
            sample=self.sample,
            p_type=["PT_PHDR", "PT_INTERP"],
            p_offset=[64, 736],
            p_flags=[4, 4],
            p_vaddr=[64, 736],
            p_paddr=[64, 736],
            p_filesz=[672, 28],
            p_memsz=[672, 28],
            p_align=[8, 1]
        )

    def test_elfprogramheader_update(self):
        """
        This test updates an entry in the ELFProgramHeader table.
        """
        ephdr = ELFProgramHeader.objects.create(
            sample=self.sample,
            p_type=["PT_PHDR", "PT_INTERP"],
            p_offset=[64, 726],
            p_flags=[4, 6],
            p_vaddr=[64, 236],
            p_paddr=[64, 236],
            p_filesz=[672, 18],
            p_memsz=[672, 18],
            p_align=[8, 1]
        )

        updated_p_type = ["PT_PHDR", "PT_DYNAMIC"]
        ephdr.p_type = updated_p_type
        ephdr.save()

        ephdr = ELFProgramHeader.objects.get(sample=self.sample)
        self.assertEqual(ephdr.p_type, updated_p_type)

    def test_elfprogramheader_delete(self):
        """
        This test deletes an entry in the ELFProgramHeader table.
        """
        ephdr = ELFProgramHeader.objects.create(
            sample=self.sample,
            p_type=["PT_PHDR", "PT_INTERP"],
            p_offset=[64, 736],
            p_flags=[4, 4],
            p_vaddr=[64, 736],
            p_paddr=[64, 736],
            p_filesz=[672, 28],
            p_memsz=[672, 28],
            p_align=[8, 1]
        )
        ephdr.delete()

        try:
            ELFProgramHeader.objects.get(sample=self.sample)
            self.fail('ELFHeader object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_duplicate_elfprogramheader(self):
        """
        If a sample is analyzed twice, their ELFProgramHeader entries should still be
        the same, i.e., if two ELFProgramHeader objects are created for the same sample
        object, it should result in django.db.utils.IntegrityError exception. This
        is because ELFProgramHeader.sample is a OneToOneField.
        """

        ELFProgramHeader.objects.create(
            sample=self.sample,
            p_type=["PT_PHDR", "PT_INTERP"],
            p_offset=[64, 736],
            p_flags=[4, 4],
            p_vaddr=[64, 736],
            p_paddr=[64, 736],
            p_filesz=[672, 28],
            p_memsz=[672, 28],
            p_align=[8, 1]
        )

        try:
            ELFProgramHeader.objects.create(
                sample=self.sample,
                p_type=["PT_PHDR", "PT_INTERP"],
                p_offset=[64, 736],
                p_flags=[4, 4],
                p_vaddr=[64, 736],
                p_paddr=[64, 736],
                p_filesz=[672, 28],
                p_memsz=[672, 28],
                p_align=[8, 1]
            )
            self.fail('Duplicate ELFProgramHeader entry should not have been created in DB')
        except IntegrityError:
            pass
