from django.test import TestCase
from analysis.models import Detection


class DetectionTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        cls.score = 30
        Detection.objects.create(score=cls.score)

    def test_detection_get(self):
        """
        This test checks if the Detection object can be successfully
        retrieved. There should be only 1.
        """
        objs = Detection.objects.filter(score=self.score)
        self.assertEqual(len(objs), 1)

    def test_detection_update(self):
        """
        This test updates an existing Detection entry.
        """
        objs = Detection.objects.filter(score=self.score)
        self.assertEqual(len(objs), 1)

        detection = objs[0]
        new_score = 70
        detection.score = new_score
        detection.save()

        obj = Detection.objects.filter(score=new_score)[0]
        self.assertEqual(obj.score, new_score)

    def test_detection_delete(self):
        """
        This test checks if an existing Detection object can be deleted.
        It should be, since *currently* there are no other db objects
        referencing this Detection object.
        """
        objs = Detection.objects.filter(score=self.score)
        self.assertEqual(len(objs), 1)

        detection = objs[0]
        detection.delete()

        objs = Detection.objects.filter(score=self.score)
        self.assertEqual(len(objs), 0)
