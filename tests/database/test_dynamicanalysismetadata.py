import uuid
import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.dynamic_analysis import DynamicAnalysisMetadata

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class DynamicAnalysisMetadataTestCase(TestCase):
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
        DynamicAnalysisMetadata.objects.create(
            sample=cls.sample,
            filename="test.elf",
            console_output=b"test",
            sample_pid=1337
        )

    def test_dynamicanalysismetadata_get(self):
        """
        This test checks if created DynamicAnalysisMetadata object can be retrieved
        successfully from the DB.
        """
        dynamic_metadata = DynamicAnalysisMetadata.objects.get(sample=self.sample)
        self.assertEqual(dynamic_metadata.sample.sha256, self.sha256)

    def test_dynamicanalysismetadata_update(self):
        """
        This test checks if created DynamicAnalysisMetadata object can be updated
        successfully.
        """
        dynamic_metadata = DynamicAnalysisMetadata.objects.get(sample=self.sample)

        new_sample_pid = 7331
        dynamic_metadata.sample_pid = new_sample_pid
        dynamic_metadata.save()

        dynamic_metadata = DynamicAnalysisMetadata.objects.get(sample=self.sample)
        self.assertEqual(dynamic_metadata.sample_pid, new_sample_pid)

    def test_dynamicanalysismetadata_delete(self):
        """
        This test checks if an existing DynamicAnalysisMetadata object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this DynamicAnalysisMetadata object.
        """
        dynamic_metadata = DynamicAnalysisMetadata.objects.get(sample=self.sample)
        dynamic_metadata.delete()

        try:
            DynamicAnalysisMetadata.objects.get(sample=self.sample)
            self.fail('DynamicAnalysisMetadata object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_dynamicanalysismetadata_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the DynamicAnalysisMetadata
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass
