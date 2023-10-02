import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.dynamic_analysis import DynamicAnalysisReports,\
    DynamicAnalysisMetadata, KernelTrace, UserlandTrace, MemoryStrings

from django.db.utils import IntegrityError


class DynamicAnalysisReportsTestCase(TestCase):
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

    def test_dynamicanalysisreports_onetoone_dynamicanalysismetadata_cannot_delete(self):
        """
        This test checks if the DynamicAnalysisMetadata object referenced by the
        DynamicAnalysisReports object can be deleted. It should not be, since there
        is a foreign key constraint with on_delete=models.PROTECT.
        """
        metadata_obj = DynamicAnalysisMetadata.objects.create(
            sample=self.sample,
            filename="test.elf",
            console_output=b"test",
            sample_pid=1337
        )
        DynamicAnalysisReports.objects.create(metadata=metadata_obj)

        try:
            metadata_obj.delete()
            self.fail("DynamicAnalysisMetadata object deleted in database")
        except IntegrityError:
            pass

    def test_dynamicanalysisreports_onetoone_kerneltrace_cannot_delete(self):
        """
        This test checks if the KernelTrace object referenced by the
        DynamicAnalysisReports object can be deleted. It should not be, since
        there is a foreign key constraint with on_delete=models.PROTECT.
        """
        kerneltrace_obj = KernelTrace.objects.create()
        DynamicAnalysisReports.objects.create(kernel_trace=kerneltrace_obj)

        try:
            kerneltrace_obj.delete()
            self.fail("KernelTrace object deleted in database")
        except IntegrityError:
            pass

    def test_dynamicanalysisreports_onetoone_userlandtrace_cannot_delete(self):
        """
        This test checks if the UserlandTrace object referenced by the
        DynamicAnalysisReports object can be deleted. It should not be, since
        there is a foreign key constraint with on_delete=models.PROTECT.
        """
        userlandtrace_obj = UserlandTrace.objects.create()
        DynamicAnalysisReports.objects.create(userland_trace=userlandtrace_obj)

        try:
            userlandtrace_obj.delete()
            self.fail("UserlandTrace object deleted in database")
        except IntegrityError:
            pass

    def test_dynamicanalysisreports_foreignkey_memstrings_delete(self):
        """
        This test checks if the UserlandTrace object referenced by the
        DynamicAnalysisReports object can be deleted. It should be, since
        there is a foreign key constraint with on_delete=models.CASCADE.
        """
        obj = MemoryStrings.objects.create(sample=self.sample)
        DynamicAnalysisReports.objects.create(memstrings=obj)

        try:
            obj.delete()
        except IntegrityError:
            self.fail("UserlandTrace object not deleted in database")
