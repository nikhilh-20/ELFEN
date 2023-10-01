import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import AntiStaticAnalysis

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class AntiStaticAnalysisTestCase(TestCase):
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
        AntiStaticAnalysis.objects.create(
            sample=cls.sample,
            readelf="Something is wrong"
        )

    def test_antistaticanalysis_get(self):
        """
        This test checks if the created AntiStaticAnalysis object can be
        successfully retrieved from the DB.
        """
        anti_static_analysis = AntiStaticAnalysis.objects.get(sample=self.sample)
        self.assertEqual(anti_static_analysis.sample.sha256, self.sha256)

    def test_antistaticanalysis_update(self):
        """
        This test updates AntiStaticAnalysis object's strs property.
        """
        anti_static_analysis = AntiStaticAnalysis.objects.get(sample=self.sample)
        new_readelf_msg = "Something else is wrong"

        anti_static_analysis.readelf = new_readelf_msg
        anti_static_analysis.save()

        anti_static_analysis = AntiStaticAnalysis.objects.get(sample=self.sample)
        self.assertEqual(anti_static_analysis.readelf, new_readelf_msg)

    def test_antistaticanalysis_delete(self):
        """
        This test checks if an existing AntiStaticAnalysis object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this AntiStaticAnalysis object.
        """
        anti_static_analysis = AntiStaticAnalysis.objects.get(sample=self.sample)
        anti_static_analysis.delete()

        try:
            AntiStaticAnalysis.objects.get(sample=self.sample)
            self.fail("AntiStaticAnalysis object not deleted in database")
        except ObjectDoesNotExist:
            pass

    def test_antistaticanalysis_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the AntiStaticAnalysis
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail("SampleMetadata object deleted in database")
        except IntegrityError:
            pass
