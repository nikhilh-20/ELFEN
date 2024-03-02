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
from django.contrib.postgres import fields

from web.models import SampleMetadata
from analysis.analysis_models.utils import TaskStatusChoices
from analysis.enum import *


class RRSection:
    QD = 0
    AN = 1
    NS = 2
    AR = 3


class RRSectionDesc:
    QD = "Question Section"
    AN = "Answer Section"
    NS = "Name Server Section"
    AR = "Additional Records Section"


class RRSectionChoices(models.TextChoices):
    QD = RRSection.QD, RRSectionDesc.QD
    AN = RRSection.AN, RRSectionDesc.AN
    NS = RRSection.NS, RRSectionDesc.NS
    AR = RRSection.AR, RRSectionDesc.AR


rrsection_mapping = {
    RRSection.QD: RRSectionDesc.QD,
    RRSection.AN: RRSectionDesc.AN,
    RRSection.NS: RRSectionDesc.NS,
    RRSection.AR: RRSectionDesc.AR,
}


rcode_mapping = {
    0: "No Error", 1: "Format Error", 2: "Server Failure", 3: "Name Error",
    4: "Not Implemented", 5: "Refused"
}


class PcapAnalysis(models.Model):
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class DnsQuery(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    pcapanalysis = models.ForeignKey(PcapAnalysis, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    # Domains can be max 255 octets long
    txid = models.PositiveIntegerField()
    flags = models.PositiveIntegerField()
    qdcount = models.PositiveSmallIntegerField()
    ancount = models.PositiveSmallIntegerField()
    nscount = models.PositiveSmallIntegerField()
    arcount = models.PositiveSmallIntegerField()
    # Resource record section
    rrsection = models.SmallIntegerField(choices=RRSectionChoices.choices,
                                         default=RRSection.QD)
    # Domains can be max 255 octets long
    query_domain = models.CharField(max_length=255, null=True)
    query_type = models.CharField(max_length=8, null=True)
    query_class = models.CharField(max_length=8, null=True)
    # To store EDNS0 data, for example
    opt_data = fields.ArrayField(models.JSONField(null=True), null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class DnsResponse(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    pcapanalysis = models.ForeignKey(PcapAnalysis, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    # Domains can be max 255 octets long
    txid = models.PositiveIntegerField()
    flags = models.PositiveIntegerField()
    rcode = models.PositiveSmallIntegerField()
    qdcount = models.PositiveSmallIntegerField()
    ancount = models.PositiveSmallIntegerField()
    nscount = models.PositiveSmallIntegerField()
    arcount = models.PositiveSmallIntegerField()
    # Resource record section
    rrsection = models.SmallIntegerField(choices=RRSectionChoices.choices,
                                         default=RRSection.QD, null=True)
    response_type = models.CharField(max_length=8, null=True)
    response_class = models.CharField(max_length=8, null=True)
    response_ttl = models.IntegerField(null=True)
    response_data = models.CharField(max_length=4096, null=True)
    opt_data = fields.ArrayField(models.JSONField(null=True), null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


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
