import uuid
import hashlib
import datetime

from django.test import TestCase
from web.models import SampleMetadata
from analysis.enum import TaskStatus
from analysis.models import TaskMetadata, Detection

from django.db.utils import IntegrityError
from django.core.exceptions import ObjectDoesNotExist


class TaskMetadataTestCase(TestCase):
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
        TaskMetadata.objects.create(
            uuid=cls.uuid1,
            sha256=cls.sample,
            userland_tracing=True,
            status=TaskStatus.IN_PROGRESS,
            start_time=datetime.datetime.strptime("2022-12-19T17:17:34+00:00",
                                                  "%Y-%m-%dT%H:%M:%S%z"),
        )

    def test_get_task_uuid(self):
        """
        This test checks if created metadata can be successfully retrieved
        from the TaskMetadata table in metadata DB.
        """
        task = TaskMetadata.objects.get(uuid=self.uuid1)
        self.assertEqual(task.sha256.sha256, self.sha256)

    def test_create_task_duplicate_sample_submission(self):
        """
        This test checks if a task can be created for a duplicate sample
        submission. It should be.
        """
        TaskMetadata.objects.create(
            uuid=uuid.uuid4(),
            sha256=self.sample,
            userland_tracing=True,
            status=TaskStatus.IN_PROGRESS,
            start_time=datetime.datetime.strptime("2022-12-13T17:16:34+00:00",
                                                  "%Y-%m-%dT%H:%M:%S%z"),
            end_time=None,
        )

    def test_get_sample_all_tasks(self):
        """
        Given a sample SHA256, get all associated analysis. There should be
        just 1.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        self.assertNotEqual(sample, None)
        tasks = TaskMetadata.objects.filter(sha256=sample)
        self.assertEqual(len(tasks), 1)

    def test_get_all_inprogress_tasks(self):
        """
        Given a sample SHA256, get all associated in-progress analysis. There
        should be just 1.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        tasks = TaskMetadata.objects.\
            filter(sha256=sample).\
            filter(status=TaskStatus.IN_PROGRESS)
        self.assertEqual(len(tasks), 1)

    def test_task_update(self):
        """
        This test updates an in-progress task. It marks it complete and sets
        the end time.
        """
        end_time = datetime.datetime.strptime("2022-12-13T17:16:38+00:00",
                                              "%Y-%m-%dT%H:%M:%S%z")
        task = TaskMetadata.objects.get(uuid=self.uuid1)
        self.assertEqual(task.status, TaskStatus.IN_PROGRESS)

        task.status = TaskStatus.COMPLETE
        task.end_time = end_time
        task.save()

        task = TaskMetadata.objects.get(uuid=self.uuid1)
        self.assertEqual(task.status, TaskStatus.COMPLETE)
        self.assertEqual(task.end_time, end_time)

    def test_task_delete(self):
        """
        This test checks if an existing task can be deleted. It should be, since
        *currently* there are no other db objects referencing this TaskMetadata
        object.
        """
        task = TaskMetadata.objects.get(uuid=self.uuid1)
        task.delete()

        try:
            TaskMetadata.objects.get(uuid=self.uuid1)
            self.fail("Task object not deleted in database")
        except ObjectDoesNotExist:
            pass

    def test_taskmetadata_foreignkey_sample_cannot_delete(self):
        """
        This test checks if the SampleMetadata object referenced by the TaskMetadata
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        sample = SampleMetadata.objects.get(sha256=self.sha256)
        try:
            sample.delete()
            self.fail("SampleMetadata object deleted in database")
        except IntegrityError:
            pass

    def test_taskmetadata_foreignkey_detection_cannot_delete(self):
        """
        This test checks if the Detection object referenced by the TaskMetadata
        object can be deleted. It should not be, since there is a foreign key constraint
        with on_delete=models.PROTECT.
        """
        detection = Detection.objects.create()
        task = TaskMetadata.objects.get(uuid=self.uuid1)
        task.detection = detection
        task.save()

        try:
            detection.delete()
            self.fail("Detection object deleted in database")
        except IntegrityError:
            pass
