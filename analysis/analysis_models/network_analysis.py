"""
Copyright (C) 2023-2024 Nikhil Ashok Hegde (@ka1do9)

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

from web.models import SampleMetadata
from analysis.analysis_models.utils import TaskStatusChoices
from analysis.enum import *


class PcapAnalysis(models.Model):
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class DnsPacketAnalysis(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    pcapanalysis = models.ForeignKey(PcapAnalysis, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    # Domains can be max 255 octets long
    query_domain = models.CharField(max_length=255)
    query_type = models.CharField(max_length=8)
    query_class = models.CharField(max_length=8)
    response_type = models.CharField(max_length=8, null=True)
    response_class = models.CharField(max_length=8, null=True)
    response_ttl = models.IntegerField(null=True)
    response_data = models.CharField(max_length=4096, null=True)


class NetworkAnalysisReports(models.Model):
    pcapanalysis = models.OneToOneField(PcapAnalysis,
                                        on_delete=models.PROTECT, null=True)
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
