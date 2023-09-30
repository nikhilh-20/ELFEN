import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class SampleMetadataTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        test_string = b'This is a test'
        cls.md5 = hashlib.md5(test_string).hexdigest()
        cls.sha1 = hashlib.sha1(test_string).hexdigest()
        cls.sha256 = hashlib.sha256(test_string).hexdigest()
        # The below serves as a "create entry" test case
        SampleMetadata.objects.create(
            md5=cls.md5,
            sha1=cls.sha1,
            sha256=cls.sha256,
            username="test_user"
        )

    def test_get_sample(self):
        """
        This test checks if created metadata can be successfully retrieved
        from the SampleMetadata table in metadata DB.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        self.assertEqual(sample.sha256, self.sha256)
        self.assertEqual(sample.md5, self.md5)

    def test_create_incorrect_sample(self):
        """
        This test checks if an incorrect sample creation is caught. In this
        case, the "bintype" field contains an invalid entry.
        """
        test_string = b'This is an incorrect test'
        md5 = hashlib.md5(test_string).hexdigest()
        sha1 = hashlib.sha1(test_string).hexdigest()
        sha256 = hashlib.sha256(test_string).hexdigest()

        try:
            SampleMetadata.objects.create(
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                bintype="et_fail"
            )
            self.fail('SampleMetadata model failed to validate the "bintype" field')
        except IntegrityError:
            pass

    def test_sample_update(self):
        """
        This test updates an existing sample entry. Tbh, the test logic doesn't
        make sense because the SHA256 should also change when the MD5 is changed,
        but it's sufficient to check if the update action works.
        """
        new_md5 = hashlib.md5(b'This is an update test').hexdigest()
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        sample.md5 = new_md5
        sample.save()

        sample = SampleMetadata.objects.get(sha256=self.sha256)
        self.assertEqual(sample.sha256, self.sha256)
        self.assertEqual(sample.md5, new_md5)

    def test_sample_delete(self):
        """
        This test checks if an existing sample entry can be deleted.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        sample.delete()

        try:
            SampleMetadata.objects.get(sha256=self.sha256)
            self.fail('Sample object not deleted in database')
        except ObjectDoesNotExist:
            pass
