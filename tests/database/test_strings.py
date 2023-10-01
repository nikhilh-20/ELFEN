import hashlib

from django.test import TestCase
from analysis.analysis_models.static_analysis import Strings

from django.core.exceptions import ObjectDoesNotExist


class StringsTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        cls.test_string = "This is a test"
        cls.sha256 = hashlib.sha256(b"This is a test").hexdigest()
        Strings.objects.create(
            string=cls.test_string,
            sha256s=[cls.sha256]
        )

    def test_strings_get(self):
        """
        This test checks if the created Strings object can be
        successfully retrieved from the DB.
        """
        strings = Strings.objects.get(string=self.test_string)
        self.assertEqual(strings.string, self.test_string)

    def test_strings_update(self):
        """
        This test updates Strings object's sha256s property.
        """
        strings = Strings.objects.get(string=self.test_string)
        new_sha256s = [self.sha256,
                       hashlib.sha256(b"Another one").hexdigest()]

        strings.sha256s = new_sha256s
        strings.save()

        strings = Strings.objects.get(string=self.test_string)
        self.assertEqual(strings.sha256s, new_sha256s)

    def test_strings_delete(self):
        """
        This test checks if an existing Strings object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this Strings object.
        """
        strings = Strings.objects.get(string=self.test_string)
        strings.delete()

        try:
            Strings.objects.get(string=self.test_string)
            self.fail("Strings object not deleted in database")
        except ObjectDoesNotExist:
            pass
