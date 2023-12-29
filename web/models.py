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


class BinType(models.TextChoices):
    ET_NONE = "et_none", "ET_NONE"
    ET_REL = "et_rel", "ET_REL"
    ET_EXEC = "et_exec", "ET_EXEC"
    ET_DYN = "et_dyn", "ET_DYN"
    ET_CORE = "et_core", "ET_CORE"


class SampleMetadata(models.Model):
    md5 = models.CharField(max_length=32)
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64, primary_key=True)
    bintype = models.CharField(choices=BinType.choices, max_length=7, null=True)
    tlsh = models.CharField(max_length=72, null=True)
    family = fields.ArrayField(models.CharField(max_length=64), default=list)
    tags = fields.ArrayField(models.CharField(max_length=64), default=list)
    similar = fields.ArrayField(models.CharField(max_length=64), default=list)

    # Django username (django.contrib.auth) are restricted to <=150 chars
    username = models.CharField(max_length=150)
    # private = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                name="%(app_label)s_%(class)s_bintype_valid",
                check=models.Q(bintype__in=BinType.values)
            ),
        ]
