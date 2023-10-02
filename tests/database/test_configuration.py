import uuid
import hashlib
import datetime

from django.test import TestCase
from web.models import SampleMetadata
from analysis.enum import TaskStatus
from analysis.models import TaskMetadata, Configuration

from django.db.utils import IntegrityError


class ConfigurationTestCase(TestCase):
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
        cls.task = TaskMetadata.objects.create(
            uuid=cls.uuid1,
            sha256=cls.sample,
            userland_tracing=True,
            status=TaskStatus.IN_PROGRESS,
            start_time=datetime.datetime.strptime("2022-12-19T17:17:34+00:00",
                                                  "%Y-%m-%dT%H:%M:%S%z"),
        )
        Configuration.objects.create(
            sha256=cls.sample,
            parent_task=cls.task,
            ip="8.8.8.8",
            port=53
        )

    def test_configuration_get(self):
        """
        This test checks if Configuration object can be retrieved. There should
        be only 1.
        """
        objs = Configuration.objects.filter(sha256=self.sample)
        self.assertEqual(len(objs), 1)

    def test_configuration_update(self):
        """
        This test updates an existing Configuration object. It changes the port
        entry.
        """
        objs = Configuration.objects.filter(sha256=self.sample)
        self.assertEqual(len(objs), 1)

        configuration = objs[0]
        new_port = 8080
        configuration.port = new_port
        configuration.save()

        obj = Configuration.objects.filter(sha256=self.sample)[0]
        self.assertEqual(obj.port, new_port)

    def test_configuration_delete(self):
        """
        This test checks if an existing Configuration object can be deleted.
        It should be, since *currently* there are no other db objects
        referencing this Configuration object.
        """
        objs = Configuration.objects.filter(sha256=self.sample)
        self.assertEqual(len(objs), 1)

        configuration = objs[0]
        configuration.delete()

        objs = Configuration.objects.filter(sha256=self.sample)
        self.assertEqual(len(objs), 0)

    def test_configuration_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the Configuration
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail("SampleMetadata object deleted in database")
        except IntegrityError:
            pass

    def test_configuration_foreignkey_task_cannot_delete(self):
        """
        This test checks if the TaskMetadata object referenced by the Configuration
        object can be deleted. It should not be, since there is a foreign key
        constraint with on_delete=models.PROTECT.
        """
        task = TaskMetadata.objects.get(uuid=self.uuid1)

        try:
            task.delete()
            self.fail("TaskMetadata object deleted in database")
        except IntegrityError:
            pass
