import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import PrintableStrings

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class PrintableStringsTestCase(TestCase):
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
            username="test_user"
        )
        PrintableStrings.objects.create(
            sample=cls.sample,
            strs=["test"]
        )

    def test_printablestrings_get(self):
        """
        This test checks if the created PrintableStrings object can be
        successfully retrieved from the DB.
        """
        printable_strings = PrintableStrings.objects.get(sample=self.sample)
        self.assertEqual(printable_strings.sample.sha256, self.sha256)

    def test_printablestrings_update(self):
        """
        This test updates PrintableStrings object's strs property.
        """
        printable_strings = PrintableStrings.objects.get(sample=self.sample)
        new_strs = ["test1", "test2"]

        printable_strings.strs = new_strs
        printable_strings.save()

        self.assertEqual(printable_strings.strs, new_strs)

    def test_printablestrings_delete(self):
        """
        This test checks if an existing PrintableStrings object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this PrintableStrings object.
        """
        printable_strings = PrintableStrings.objects.get(sample=self.sample)
        printable_strings.delete()

        try:
            PrintableStrings.objects.get(sample=self.sample)
            self.fail('PrintableStrings object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_printablestrings_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the PrintableStrings
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass
