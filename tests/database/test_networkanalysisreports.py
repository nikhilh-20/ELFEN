from django.test import TestCase
from analysis.enum import TaskStatus
from analysis.models import NetworkAnalysisReports


class NetworkAnalysisReportsTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        NetworkAnalysisReports.objects.create(
            status=TaskStatus.IN_PROGRESS
        )

    def test_networkanalysisreports_get(self):
        """
        This test checks if the NetworkAnalysisReports object can be successfully
        retrieved. There should be only 1.
        """
        objs = NetworkAnalysisReports.objects.filter(status=TaskStatus.IN_PROGRESS)
        self.assertEqual(len(objs), 1)

    def test_networkanalysisreports_update(self):
        """
        This test updates an existing NetworkAnalysisReports entry.
        """
        objs = NetworkAnalysisReports.objects.filter(status=TaskStatus.IN_PROGRESS)
        self.assertEqual(len(objs), 1)

        network_report = objs[0]
        network_report.status = TaskStatus.COMPLETE
        network_report.save()

        obj = NetworkAnalysisReports.objects.filter(status=TaskStatus.COMPLETE)[0]
        self.assertEqual(obj.status, TaskStatus.COMPLETE)

    def test_networkanalysisreports_delete(self):
        """
        This test checks if an existing NetworkAnalysisReports object can be deleted.
        It should be, since *currently* there are no other db objects
        referencing this NetworkAnalysisReports object.
        """
        objs = NetworkAnalysisReports.objects.filter(status=TaskStatus.IN_PROGRESS)
        self.assertEqual(len(objs), 1)

        network_report = objs[0]
        network_report.delete()

        objs = NetworkAnalysisReports.objects.filter(status=TaskStatus.IN_PROGRESS)
        self.assertEqual(len(objs), 0)
