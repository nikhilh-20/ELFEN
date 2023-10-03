import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.static_analysis import CapaCapabilities

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class CapaCapabilitiesTestCase(TestCase):
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
        CapaCapabilities.objects.create(
            sample=cls.sample,
            base_address=0x401000
        )

    def test_capacapabilities_get(self):
        """
        This test checks if the created CapaCapabilities object can be
        successfully retrieved from the DB.
        """
        capa = CapaCapabilities.objects.get(sample=self.sample)
        self.assertEqual(capa.sample.sha256, self.sha256)

    def test_capacapabilities_update(self):
        """
        This test updates CapaCapabilities object's base_address property.
        """
        capa = CapaCapabilities.objects.get(sample=self.sample)

        new_base_address = 0x501000
        capa.base_address = new_base_address
        capa.save()

        capa = CapaCapabilities.objects.get(sample=self.sample)
        self.assertEqual(capa.base_address, new_base_address)

    def test_capacapabilities_delete(self):
        """
        This test checks if an existing CapaCapabilities object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this CapaCapabilities object.
        """
        capa = CapaCapabilities.objects.get(sample=self.sample)
        capa.delete()

        try:
            CapaCapabilities.objects.get(sample=self.sample)
            self.fail('CapaCapabilities object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_capacapabilities_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the CapaCapabilities
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass
