import hashlib

from django.test import TestCase
from analysis.analysis_models.static_analysis import *

from django.db.utils import IntegrityError


class StaticAnalysisReportsTestCase(TestCase):
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

    def test_staticanalysisreports_foreignkey_elfheader_delete(self):
        """
        This test checks if the ELFHeader object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        eh = ELFHeader.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(elfheader=eh)

        try:
            eh.delete()
        except IntegrityError:
            self.fail("ELFHeader object not deleted in database")

    def test_staticanalysisreports_foreignkey_elfprogheader_delete(self):
        """
        This test checks if the ELFProgramHeader object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        phdr = ELFProgramHeader.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(elfprogheader=phdr)

        try:
            phdr.delete()
        except IntegrityError:
            self.fail("ELFProgramHeader object not deleted in database")

    def test_staticanalysisreports_foreignkey_elfsectionheader_delete(self):
        """
        This test checks if the ELFSectionHeader object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        shdr = ELFSectionHeader.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(elfsectionheader=shdr)

        try:
            shdr.delete()
        except IntegrityError:
            self.fail("ELFSectionHeader object not deleted in database")

    def test_staticanalysisreports_foreignkey_capacapabilities_delete(self):
        """
        This test checks if the CapaCapabilities object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        capa = CapaCapabilities.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(capa=capa)

        try:
            capa.delete()
        except IntegrityError:
            self.fail("CapaCapabilities object not deleted in database")

    def test_staticanalysisreports_foreignkey_samplefeatures_delete(self):
        """
        This test checks if the SampleFeatures object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        sample_features = SampleFeatures.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(samplefeatures=sample_features)

        try:
            sample_features.delete()
        except IntegrityError:
            self.fail("SampleFeatures object not deleted in database")

    def test_staticanalysisreports_foreignkey_staticantianalysis_delete(self):
        """
        This test checks if the AntiStaticAnalysis object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        anti_static_analysis = AntiStaticAnalysis.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(staticantianalysis=anti_static_analysis)

        try:
            anti_static_analysis.delete()
        except IntegrityError:
            self.fail("AntiStaticAnalysis object not deleted in database")

    def test_staticanalysisreports_foreignkey_printablestrings_delete(self):
        """
        This test checks if the PrintableStrings object referenced by the StaticAnalysisReports
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        printable_strings = PrintableStrings.objects.create(sample=self.sample)
        StaticAnalysisReports.objects.create(strings=printable_strings)

        try:
            printable_strings.delete()
        except IntegrityError:
            self.fail("PrintableStrings object not deleted in database")

