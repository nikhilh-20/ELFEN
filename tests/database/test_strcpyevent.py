import uuid
import hashlib

from django.test import TestCase
from web.models import SampleMetadata
from analysis.analysis_models.dynamic_analysis import StrcpyEvent, UserlandTrace

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class StrcpyEventTestCase(TestCase):
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
        cls.userland_trace = UserlandTrace.objects.create()
        StrcpyEvent.objects.create(
            sample=cls.sample,
            userland_trace=cls.userland_trace,
            procname=b"test"
        )

    def test_strcpyevent_get(self):
        """
        This test checks if created StrcpyEvent object can be retrieved
        successfully from the DB.
        """
        event = StrcpyEvent.objects.get(sample=self.sample)
        self.assertEqual(event.sample.sha256, self.sha256)

    def test_strcpyevent_update(self):
        """
        This test checks if created StrcpyEvent object can be updated
        successfully.
        """
        event = StrcpyEvent.objects.get(sample=self.sample)

        new_procname = b"test2"
        event.procname = new_procname
        event.save()

        event = StrcpyEvent.objects.get(sample=self.sample)
        self.assertEqual(event.procname.tobytes(), new_procname)

    def test_strcpyevent_delete(self):
        """
        This test checks if an existing StrcpyEvent object can be deleted.
        It should be, since *currently* there are no other db objects referencing
        this StrcpyEvent object.
        """
        event = StrcpyEvent.objects.get(sample=self.sample)
        event.delete()

        try:
            StrcpyEvent.objects.get(sample=self.sample)
            self.fail('StrcpyEvent object not deleted in database')
        except ObjectDoesNotExist:
            pass

    def test_strcpyevent_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the StrcpyEvent
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail('SampleMetadata object deleted in database')
        except IntegrityError:
            pass

    def test_strcpyevent_foreignkey_userlandtrace_delete(self):
        """
        This test checks if the UserlandTrace object referenced by the StrcpyEvent
        object can be deleted. It should be, since there is a foreign key constraint
        with on_delete=models.CASCADE.
        """
        event = StrcpyEvent.objects.get(sample=self.sample)
        userland_trace = event.userland_trace
        try:
            userland_trace.delete()
        except IntegrityError:
            self.fail('UserlandTrace object not deleted in database')
