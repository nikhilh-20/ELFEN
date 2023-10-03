import uuid
import hashlib
import datetime

from django.test import TestCase
from web.models import SampleMetadata
from analysis.enum import TaskStatus
from analysis.analysis_models.dynamic_analysis import MemoryStrings

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class MemoryStringsTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        test_string = b"This is a test"
        cls.md5 = hashlib.md5(test_string).hexdigest()
        cls.sha1 = hashlib.sha1(test_string).hexdigest()
        cls.sha256 = hashlib.sha256(test_string).hexdigest()
        cls.uuid1 = uuid.uuid4()
        cls.sample = SampleMetadata.objects.create(
            md5=cls.md5,
            sha1=cls.sha1,
            sha256=cls.sha256,
            username="test_user"
        )
        MemoryStrings.objects.create(
            sample=cls.sample,
            strs=["test"]
        )

    def test_memorystrings_get(self):
        """
        This test checks if created MemoryStrings object can be retrieved
        successfully from the DB.
        """
        mem_str = MemoryStrings.objects.get(sample=self.sample)
        self.assertEqual(mem_str.sample.sha256, self.sha256)

    def test_memorystrings_update(self):
        """
        This test checks if created MemoryStrings object can be updated
        successfully.
        """
        mem_str = MemoryStrings.objects.get(sample=self.sample)

        new_strs = ["test1", "test2"]
        mem_str.strs = new_strs
        mem_str.save()

        mem_str = MemoryStrings.objects.get(sample=self.sample)
        self.assertEqual(mem_str.strs, new_strs)

    def test_memorystrings_delete(self):
        """
        This test checks if an existing MemoryStrings object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this MemoryStrings object.
        """
        mem_str = MemoryStrings.objects.get(sample=self.sample)
        mem_str.delete()

        try:
            MemoryStrings.objects.get(sample=self.sample)
            self.fail('MemoryStrings object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_memorystrings_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the MemoryStrings
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass
