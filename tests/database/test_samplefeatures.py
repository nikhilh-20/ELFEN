import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import SampleFeatures

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class SampleFeaturesTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        test_string = b"This is a test"
        cls.md5 = hashlib.md5(test_string).hexdigest()
        cls.sha1 = hashlib.sha1(test_string).hexdigest()
        cls.sha256 = hashlib.sha256(test_string).hexdigest()
        cls.sample = SampleMetadata.objects.create(
            md5=cls.md5,
            sha1=cls.sha1,
            sha256=cls.sha256,
            username="test_user"
        )
        SampleFeatures.objects.create(
            sample=cls.sample,
            num_sections=2
        )

    def test_samplefeatures_get(self):
        """
        This test checks if the created SampleFeatures object can be
        successfully retrieved from the DB.
        """
        sample_features = SampleFeatures.objects.get(sample=self.sample)
        self.assertEqual(sample_features.sample.sha256, self.sha256)

    def test_samplefeatures_update(self):
        """
        This test updates SampleFeatures object's strs property.
        """
        sample_features = SampleFeatures.objects.get(sample=self.sample)
        new_num_sections = 31

        sample_features.num_sections = new_num_sections
        sample_features.save()

        sample_features = SampleFeatures.objects.get(sample=self.sample)
        self.assertEqual(sample_features.num_sections, new_num_sections)

    def test_samplefeatures_delete(self):
        """
        This test checks if an existing SampleFeatures object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this SampleFeatures object.
        """
        sample_features = SampleFeatures.objects.get(sample=self.sample)
        sample_features.delete()

        try:
            SampleFeatures.objects.get(sample=self.sample)
            self.fail("SampleFeatures object not deleted in database")
        except ObjectDoesNotExist:
            pass

    def test_samplefeatures_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the SampleFeatures
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail("SampleMetadata object deleted in database")
        except IntegrityError:
            pass
