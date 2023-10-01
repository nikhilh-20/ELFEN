import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import AntiAntiStaticAnalysis

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class AntiAntiStaticAnalysisTestCase(TestCase):
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
        AntiAntiStaticAnalysis.objects.create(
            sample=cls.sample,
            elflepton=False
        )

    def test_antiantistaticanalysis_get(self):
        """
        This test checks if the created AntiAntiStaticAnalysis object can be
        successfully retrieved from the DB.
        """
        anti_anti_static_analysis = AntiAntiStaticAnalysis.objects.get(sample=self.sample)
        self.assertEqual(anti_anti_static_analysis.sample.sha256, self.sha256)

    def test_antiantistaticanalysis_update(self):
        """
        This test updates AntiAntiStaticAnalysis object's strs property.
        """
        anti_anti_static_analysis = AntiAntiStaticAnalysis.objects.get(sample=self.sample)
        new_elflepton = True

        anti_anti_static_analysis.elflepton = new_elflepton
        anti_anti_static_analysis.save()

        anti_anti_static_analysis = AntiAntiStaticAnalysis.objects.get(sample=self.sample)
        self.assertEqual(anti_anti_static_analysis.elflepton, new_elflepton)

    def test_antiantistaticanalysis_delete(self):
        """
        This test checks if an existing AntiAntiStaticAnalysis object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this AntiAntiStaticAnalysis object.
        """
        anti_anti_static_analysis = AntiAntiStaticAnalysis.objects.get(sample=self.sample)
        anti_anti_static_analysis.delete()

        try:
            AntiAntiStaticAnalysis.objects.get(sample=self.sample)
            self.fail("AntiAntiStaticAnalysis object not deleted in database")
        except ObjectDoesNotExist:
            pass

    def test_antiantistaticanalysis_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the AntiAntiStaticAnalysis
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail("SampleMetadata object deleted in database")
        except IntegrityError:
            pass
