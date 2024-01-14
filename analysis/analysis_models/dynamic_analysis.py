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

from django.contrib.postgres import fields
from web.models import SampleMetadata
from analysis.analysis_models.utils import *


class KernelTrace(models.Model):
    pass


class UserlandTrace(models.Model):
    pass


class ForkEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    retval = models.SmallIntegerField(null=True)


class PrctlEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    option = models.IntegerField(null=True)
    # arg2 may contain a string
    arg2 = models.BinaryField(max_length=128, null=True)
    arg3 = models.BigIntegerField(null=True)
    arg4 = models.BigIntegerField(null=True)
    arg5 = models.BigIntegerField(null=True)


class GetPidEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    retval = models.SmallIntegerField(null=True)


class GetPPidEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    retval = models.SmallIntegerField(null=True)


class ExecveEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    exec_path = models.BinaryField(max_length=128, null=True)
    arg1 = models.BinaryField(max_length=256, null=True)
    arg2 = models.BinaryField(max_length=256, null=True)


class ReadEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    # ply might report fd == -1 in its unsigned form which is 4294967295
    # and this is why I use BigIntegerField. Another way - I should convert
    # it into -1 and then store it into IntegerField, thus saving space.
    fd = models.BigIntegerField(null=True)
    buffer = models.BinaryField(max_length=128, null=True)
    size = models.PositiveIntegerField(null=True)


class ReadlinkEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    file_path = models.BinaryField(max_length=128, null=True)
    buffer = models.BinaryField(max_length=128, null=True)
    retval = models.IntegerField(null=True)


class UnlinkEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    file_path = models.BinaryField(max_length=128, null=True)


class WriteEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    buffer = models.BinaryField(max_length=128, null=True)
    size = models.PositiveIntegerField(null=True)


class OpenEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    file_path = models.BinaryField(max_length=128, null=True)
    flags = models.BigIntegerField(null=True)
    fd = models.BigIntegerField(null=True)


class RenameEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    oldfile_path = models.BinaryField(max_length=128, null=True)
    newfile_path = models.BinaryField(max_length=128, null=True)


class FcntlEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    cmd = models.IntegerField(null=True)
    arg = models.BigIntegerField(null=True)


class SocketEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    domain = models.IntegerField(null=True)
    type = models.IntegerField(null=True)
    protocol = models.IntegerField(null=True)
    fd = models.BigIntegerField(null=True)


class SetSockOptEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    level = models.IntegerField(null=True)
    option_name = models.IntegerField(null=True)
    option_value = models.BinaryField(max_length=128, null=True)
    option_len = models.IntegerField(null=True)


class BindEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    family = models.PositiveIntegerField(null=True)
    ip = models.CharField(max_length=16, null=True)
    port = models.IntegerField(null=True)
    retval = models.IntegerField(null=True)


class ConnectEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    family = models.PositiveIntegerField(null=True)
    ip = models.CharField(max_length=16, null=True)
    port = models.IntegerField(null=True)
    retval = models.IntegerField(null=True)


class ListenEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.IntegerField(null=True)
    backlog = models.IntegerField(null=True)


class SendToEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    buffer = models.BinaryField(max_length=128, null=True)
    size = models.PositiveIntegerField(null=True)


class RecvFromEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    kernel_trace = models.ForeignKey(KernelTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    pid = models.PositiveSmallIntegerField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    fd = models.BigIntegerField(null=True)
    buffer = models.BinaryField(max_length=128, null=True)
    size = models.PositiveIntegerField(null=True)


class StrcmpEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    userland_trace = models.ForeignKey(UserlandTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    str1 = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)
    str2 = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)


class StrncmpEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    userland_trace = models.ForeignKey(UserlandTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    str1 = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)
    str2 = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)
    len = models.SmallIntegerField(null=True)


class StrstrEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    userland_trace = models.ForeignKey(UserlandTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    haystack = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)
    needle = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)


class StrcpyEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    userland_trace = models.ForeignKey(UserlandTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    src = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)


class StrncpyEvent(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    userland_trace = models.ForeignKey(UserlandTrace, on_delete=models.CASCADE)
    ts = models.TimeField(null=True)
    procname = models.BinaryField(max_length=128, null=True)
    src = models.CharField(max_length=USERLAND_STR_MAXLEN, null=True)
    len = models.SmallIntegerField(null=True)


class DynamicAnalysisMetadata(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    filename = models.CharField(max_length=128)
    console_output = models.BinaryField()
    sample_pid = models.SmallIntegerField()


class MemoryStrings(models.Model):
    sample = models.ForeignKey(SampleMetadata, on_delete=models.PROTECT)
    strs = fields.ArrayField(models.CharField(max_length=4096), null=True)
    errors = models.BooleanField(default=False)
    error_msg = models.CharField(max_length=4096, default="")
    status = models.SmallIntegerField(choices=TaskStatusChoices.choices,
                                      default=TaskStatus.NOT_STARTED)


class DynamicAnalysisReports(models.Model):
    metadata = models.OneToOneField(DynamicAnalysisMetadata,
                                    on_delete=models.PROTECT, null=True)
    kernel_trace = models.OneToOneField(KernelTrace,
                                        on_delete=models.PROTECT, null=True)
    userland_trace = models.OneToOneField(UserlandTrace, on_delete=models.PROTECT,
                                          null=True)
    dropped_files = fields.ArrayField(models.CharField(max_length=128),
                                      null=True)
    memdump = models.BooleanField(default=False)
    memstrings = models.ForeignKey(MemoryStrings, on_delete=models.CASCADE, null=True)
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
