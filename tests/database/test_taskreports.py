from django.test import TestCase
from analysis.enum import TaskStatus
from analysis.models import NetworkAnalysisReports, TaskReports
from analysis.analysis_models.static_analysis import StaticAnalysisReports
from analysis.analysis_models.dynamic_analysis import DynamicAnalysisReports

from django.db.utils import IntegrityError


class TaskReportsTestCase(TestCase):
    databases = {"elfen"}

    @classmethod
    def setUpTestData(cls):
        cls.static_analysis_reports = StaticAnalysisReports.objects.create()
        cls.dynamic_analysis_reports = DynamicAnalysisReports.objects.create()
        cls.network_analysis_reports = NetworkAnalysisReports.objects.create()
        TaskReports.objects.create(
            static_reports=cls.static_analysis_reports,
            dynamic_reports=cls.dynamic_analysis_reports,
            network_reports=cls.network_analysis_reports
        )

    def test_taskreports_get(self):
        """
        This test checks if TaskReports object can be retrieved. There should
        be only 1.
        """
        objs = TaskReports.objects.filter(
            static_reports=self.static_analysis_reports
        )
        self.assertEqual(len(objs), 1)

    def test_taskreports_update(self):
        """
        This test updates an existing TaskReports object. It changes the status.
        """
        objs = TaskReports.objects.filter(
            static_reports=self.static_analysis_reports
        )
        self.assertEqual(len(objs), 1)

        taskreport = objs[0]
        taskreport.status = TaskStatus.COMPLETE
        taskreport.save()

        obj = TaskReports.objects.filter(
            static_reports=self.static_analysis_reports
        )[0]
        self.assertEqual(obj.status, TaskStatus.COMPLETE)

    def test_taskreports_delete(self):
        """
        This test checks if an existing TaskReports object can be deleted.
        It should be, since *currently* there are no other db objects
        referencing this TaskReports object.
        """
        objs = TaskReports.objects.filter(
            static_reports=self.static_analysis_reports
        )
        self.assertEqual(len(objs), 1)

        taskreport = objs[0]
        taskreport.delete()

        objs = TaskReports.objects.filter(
            static_reports=self.static_analysis_reports
        )
        self.assertEqual(len(objs), 0)

    def test_taskreports_foreignkey_staticreports_cannot_delete(self):
        """
        This test checks if the StaticAnalysisReports object referenced by the
        TaskReports object can be deleted. It should not be, since there is a
        foreign key constraint with on_delete=models.PROTECT.
        """
        try:
            self.static_analysis_reports.delete()
            self.fail("StaticAnalysisReports object deleted in database")
        except IntegrityError:
            pass

    def test_taskreports_foreignkey_dynamicreports_cannot_delete(self):
        """
        This test checks if the DynamicAnalysisReports object referenced by the
        TaskReports object can be deleted. It should not be, since there is a
        foreign key constraint with on_delete=models.PROTECT.
        """
        try:
            self.dynamic_analysis_reports.delete()
            self.fail("DynamicAnalysisReports object deleted in database")
        except IntegrityError:
            pass

    def test_taskreports_foreignkey_networkreports_cannot_delete(self):
        """
        This test checks if the NetworkAnalysisReports object referenced by the
        TaskReports object can be deleted. It should not be, since there is a
        foreign key constraint with on_delete=models.PROTECT.
        """
        try:
            self.network_analysis_reports.delete()
            self.fail("NetworkAnalysisReports object deleted in database")
        except IntegrityError:
            pass
