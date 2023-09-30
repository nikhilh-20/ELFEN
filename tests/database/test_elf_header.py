import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import ELFHeader
from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class ELFHeaderTestCase(TestCase):
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
        # Below serves as object creation test case
        ELFHeader.objects.create(
            sample=cls.sample,
            e_ident_magic=b".ELF",
            e_ident_ei_class="ELFCLASS64",
            e_ident_ei_data="ELFDATA2LSB",
            e_ident_ei_version="EV_CURRENT",
            e_ident_ei_osabi="ELFOSABI_STANDALONE",
            e_ident_ei_abiversion=1,
            e_ident_ei_pad=b"\x00\x00",
            e_ident_ei_nident=16,
            e_type="ET_DYN",
            e_machine="EM_X86_64",
            e_version="EV_CURRENT",
            e_entry=0x6043,
            e_phoff=0x32,
            e_shoff=0x5623,
            e_flags=0,
            e_ehsize=52,
            e_phentsize=52,
            e_phnum=4,
            e_shentsize=52,
            e_shnum=29,
            e_shstrndx=28,
        )

    def test_elfheader_update(self):
        """
        This test updates an entry in the ELFHeader table.
        """
        eh = ELFHeader.objects.get(sample=self.sample)

        updated_shnum = 30
        eh.e_shnum = updated_shnum
        eh.save()

        eh = ELFHeader.objects.get(sample=self.sample)
        self.assertEqual(eh.e_shnum, updated_shnum)

    def test_elfheader_delete(self):
        """
        This test deletes an entry in the ELFHeader table.
        """
        eh = ELFHeader.objects.get(sample=self.sample)
        eh.delete()

        try:
            ELFHeader.objects.get(sample=self.sample)
            self.fail('ELFHeader object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_elfheader_onetoone_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the ELFHeader
        object can be deleted. It should not be, since there is a OneToOne constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)

        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass

    def test_elfheader_duplicate(self):
        """
        If a sample is analyzed twice, their ELFHeader entries should still be
        the same, i.e., if two ELFHeader objects are created for the same sample
        object, it should result in django.db.utils.IntegrityError exception. This
        is because ELFHeader.sample is a OneToOneField.
        """
        try:
            ELFHeader.objects.create(
                sample=self.sample,
                e_ident_magic=b".ELF",
                e_ident_ei_class="ELFCLASS64",
                e_ident_ei_data="ELFDATA2LSB",
                e_ident_ei_version="EV_CURRENT",
                e_ident_ei_osabi="ELFOSABI_STANDALONE",
                e_ident_ei_abiversion=1,
                e_ident_ei_pad=b"\x00\x00",
                e_ident_ei_nident=16,
                e_type="ET_DYN",
                e_machine="EM_X86_64",
                e_version="EV_CURRENT",
                e_entry=0x6043,
                e_phoff=0x32,
                e_shoff=0x5623,
                e_flags=0,
                e_ehsize=52,
                e_phentsize=52,
                e_phnum=4,
                e_shentsize=52,
                e_shnum=29,
                e_shstrndx=28,
            )
            self.fail('Duplicate ELFHeader entry should not have been created in DB')
        except IntegrityError:
            pass
