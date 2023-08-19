"""
Copyright (C) 2023  Nikhil Ashok Hegde (@ka1do9)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from django.db import models
from django.contrib.postgres import fields

from web.models import SampleMetadata
from analysis.analysis_models.utils import TaskStatusChoices
from analysis.analysis_models.static_analysis import StaticAnalysisReports
from analysis.analysis_models.dynamic_analysis import DynamicAnalysisReports
from analysis.enum import *


class NetworkAnalysisReports(models.Model):
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_status_valid",
                check=models.Q(status__in=TaskStatusChoices.values)
            )
        ]


class TaskReports(models.Model):
    static_reports = models.OneToOneField(StaticAnalysisReports, on_delete=models.PROTECT, null=True)
    dynamic_reports = models.OneToOneField(DynamicAnalysisReports, on_delete=models.PROTECT, null=True)
    network_reports = models.OneToOneField(NetworkAnalysisReports, on_delete=models.PROTECT, null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_status_valid",
                check=models.Q(status__in=TaskStatusChoices.values)
            )
        ]


class Detection(models.Model):
    score = models.SmallIntegerField(null=True)
    static_analysis_score = models.SmallIntegerField(null=True)
    dynamic_analysis_score = models.SmallIntegerField(null=True)
    static_analysis_detectors = models.JSONField(null=True)
    dynamic_analysis_detectors = models.JSONField(null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class TaskMetadata(models.Model):
    uuid = models.CharField(max_length=36, primary_key=True)
    family = fields.ArrayField(models.CharField(max_length=64), default=list)
    # Using ForeignKey here because one sample can have multiple analyses
    # associated with it.
    sha256 = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    taskreports = models.OneToOneField(TaskReports, on_delete=models.PROTECT,
                                       null=True)
    start_time = models.DateTimeField(auto_now=True)
    end_time = models.DateTimeField(null=True)
    detection = models.ForeignKey(Detection, on_delete=models.PROTECT, null=True)
    cmdline = models.CharField(max_length=4096, null=True)
    userland_tracing = models.BooleanField()
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_status_valid",
                check=models.Q(status__in=TaskStatusChoices.values)
            )
        ]


class Configuration(models.Model):
    sha256 = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    parent_task = models.ForeignKey(TaskMetadata, on_delete=models.PROTECT)
    ip = models.CharField(max_length=15, null=True)
    port = models.IntegerField(null=True)
