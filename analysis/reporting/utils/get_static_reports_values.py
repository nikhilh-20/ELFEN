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

from analysis.enum import TaskStatus
from web.models import SampleMetadata


def _get_val(val):
    if isinstance(val, bool):
        val = str(val)
    elif isinstance(val, memoryview):
        # Binary field
        val = val.tobytes()
    elif isinstance(val, list):
        val_ = []
        for i, v in enumerate(val):
            if isinstance(v, int) or isinstance(v, str):
                val_.append(v)
            elif isinstance(v, memoryview):
                val_.append(v.tobytes())
            elif isinstance(v, list):
                val_.append(_get_val(v))
        val = val_
    elif isinstance(val, SampleMetadata):
        val = val.sha256
    elif val is None:
        val = ""
    return val


def get_elfheader_values(model, obj, exclude_fields):
    """
    Returns ELFHeader model data in the following format:
    {
        "field1": "value1",
        "field2": "value2",
        ...
    }

    :param model: ELFHeader model to pull values from
    :type model: django.db.models.base.ModelBase
    :param obj: Model object
    :type obj: analysis.analysis_models.static_analysis.ELFHeader
    :param exclude_fields: Model fields to ignore
    :type exclude_fields: tuple
    :return: ELFHeader model entry values and error message
    :rtype: tuple
    """
    data = {}
    error_msg = []

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = _get_val(getattr(obj, f.name))
            data[getattr(f, "verbose_name", f.name)] = val
        return data, error_msg

    return data, error_msg


def get_samplefeatures_values(model, obj, exclude_fields):
    """
    Returns SampleFeatures model data in the following format:
    {
        "field1": "value1",
        "field2": "value2",
        ...
    }

    :param model: SampleFeatures model to pull values from
    :type model: django.db.models.base.ModelBase
    :param obj: SampleFeatures object
    :type obj: analysis.analysis_models.static_analysis.SampleFeatures
    :param exclude_fields: Model fields to ignore
    :type exclude_fields: tuple
    :return: SampleFeatures model entry values and error message
    :rtype: tuple
    """
    data = {}
    error_msg = []

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = _get_val(getattr(obj, f.name))
            if f.name == "entry_point_bytes":
                val = repr(val)
            data[getattr(f, "verbose_name", f.name)] = val
        return data, error_msg

    return data, error_msg


def get_progheader_values(model, parent_task, exclude_fields):
    """
    Returns ELFProgramHeader model data in the following format:
    [
        {
            "row1_field1": "value1",
            "row1_field2": "value2",
            ...
        },
        {
            "row2_field1": "value1",
            "row2_field2": "value2",
            ...
        },
        ...
    ]

    :param model: ELFProgramHeader model to pull values from
    :type model: django.db.models.base.ModelBase
    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param exclude_fields: Model fields to ignore
    :type exclude_fields: tuple
    :return: ELFProgramHeader model entry values and error message
    :rtype: tuple
    """
    data = []
    data_ = {}
    error_msg = []

    sample_metadata = parent_task.sha256
    try:
        obj = model.objects.get(sample=sample_metadata)
    except (AttributeError, model.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    if obj is None:
        return data, error_msg

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = _get_val(getattr(obj, f.name))
            data_[f.name] = val

        num_progheaders = len(data_["p_type"])
        data = [{} for i in range(num_progheaders)]
        for i in range(num_progheaders):
            for f in model._meta.get_fields():
                if f.name in exclude_fields:
                    continue
                data[i][getattr(f, "verbose_name", f.name)] = data_[f.name][i]

        return data, error_msg

    return data, error_msg


def get_sectionheader_values(model, parent_task, exclude_fields):
    """
    Returns ELFSectionHeader model data in the following format:
    [
        {
            "row1_field1": "value1",
            "row1_field2": "value2",
            ...
        },
        {
            "row2_field1": "value1",
            "row2_field2": "value2",
            ...
        },
        ...
    ]

    :param model: ELFSectionHeader model to pull values from
    :type model: django.db.models.base.ModelBase
    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param exclude_fields: Model fields to ignore
    :type exclude_fields: tuple
    :return: ELFSectionHeader model entry values and error message
    :rtype: tuple
    """
    data = []
    data_ = {}
    error_msg = []

    sample_metadata = parent_task.sha256
    try:
        obj = model.objects.get(sample=sample_metadata)
    except (AttributeError, model.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    if obj is None:
        return data, error_msg

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = _get_val(getattr(obj, f.name))
            data_[f.name] = val

        num_sectionheaders = len(data_["sh_type"])
        data = [{} for i in range(num_sectionheaders)]
        for i in range(num_sectionheaders):
            for f in model._meta.get_fields():
                if f.name in exclude_fields:
                    continue
                data[i][getattr(f, "verbose_name", f.name)] = data_[f.name][i]

        return data, error_msg

    return data, error_msg


def get_capa_values(model, parent_task, backend, exclude_fields):
    """
    Returns capa capabilities in the following format:

    {
        "base_address": value,
        "matches": [
            {
                "rule": "rulename", "namespace": "namespace_name",
                "addresses": [addr1, addr2, ...]
            },
            ...
        ]
    })

    :param model: Capa model to pull values from
    :type model: django.db.models.base.ModelBase
    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param backend: Backend name in StaticAnalysisReports model
    :type backend: str
    :param exclude_fields: Model fields to ignore
    :type exclude_fields: tuple
    :return: Capa capabilities and error message
    :rtype: tuple
    """
    data = {}
    data_ = {}
    error_msg = []

    try:
        obj = getattr(parent_task.taskreports.static_reports, backend)
    except (AttributeError, model.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    if obj is None:
        return data, error_msg

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = _get_val(getattr(obj, f.name))
            data_[f.name] = val

        data.update({
            "base_address": data_["base_address"],
            "matches": []
        })
        for r, n, a in zip(data_["rules"], data_["namespaces"], data_["addresses"]):
            data["matches"].append({"rule": r, "namespace": n,
                                    "addresses": [a_ for a_ in a if a_]})

        return data, error_msg

    return data, error_msg


def get_staticantianalysis_values(model, parent_task, backend, exclude_fields):
    """
    Returns StaticAntiAnalysis model data in the following format:

    {
        "technique1": "message1",
        "technique2": "message2",
        ...
    }

    :param model: StaticAntiAnalysis model to pull values from
    :type model: django.db.models.base.ModelBase
    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param backend: Backend name in StaticAnalysisReports model
    :type backend: str
    :param exclude_fields: StaticAntiAnalysis model fields to ignore
    :type exclude_fields: tuple
    :return: StaticAntiAnalysis model entry values and error message
    :rtype: tuple
    """
    data = {}
    error_msg = []

    try:
        obj = getattr(parent_task.taskreports.static_reports, backend)
    except (AttributeError, model.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    if obj is None:
        return data, error_msg

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = getattr(obj, f.name)
            if isinstance(val, SampleMetadata):
                val = val.sha256
            if val:
                data[f.name] = val

        return data, error_msg

    return data, error_msg


def get_staticantiantianalysis_values(model, parent_task, backend, exclude_fields):
    """
    Returns StaticAntiAntiAnalysis model data in the following format:

    {
        "anti-technique1": "value1",
        "anti-technique2": "value2",
    }

    :param model: StaticAntiAntiAnalysis model to pull values from
    :type model: django.db.models.base.ModelBase
    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :param backend: Backend name in StaticAnalysisReports model
    :type backend: str
    :param exclude_fields: Model fields to ignore
    :type exclude_fields: tuple
    :return: StaticAntiAntiAnalysis model entry values and error message
    :rtype: tuple
    """
    data = {}
    error_msg = []

    try:
        obj = getattr(parent_task.taskreports.static_reports, backend)
    except (AttributeError, model.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    if obj is None:
        return data, error_msg

    if obj.status == TaskStatus.ERROR:
        error_msg = [obj.error_msg]
        return data, error_msg
    elif obj.status == TaskStatus.COMPLETE:
        for f in model._meta.get_fields():
            if f.name in exclude_fields:
                continue
            val = getattr(obj, f.name)
            if isinstance(val, SampleMetadata):
                val = val.sha256
            if val:
                data[f.name] = val

        return data, error_msg

    return data, error_msg
