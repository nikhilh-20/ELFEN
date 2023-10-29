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

import os
import logging

from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes

from web.forms import FileSubmissionForm
from web.utils import prep_file_submission
from web.tasks import start_analysis
from analysis.reporting.report import get_backend_report, get_all_reports


logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def submit_elf(request):
    """
    This API accepts file submissions from users and asynchronously
    starts analysis.

    :param request: API request from user to submit sample
    :type request: rest_framework.request.Request
    :return: Response to user
    :rtype: rest_framework.response.Response
    """
    form = FileSubmissionForm(request.POST, request.FILES)
    if form.is_valid():
        LOG.debug("POST request received to submit ELF is valid")
        file = request.FILES["file"]
        additional_files = request.FILES.getlist("additional_files")
        userland_tracing = True if request.POST.get("userland_tracing", None) else False
        enable_internet = True if request.POST.get("enable_internet", None) else False
        status, ret = prep_file_submission(file, request.user.username, request.POST["execution_time"],
                                           execution_arguments=request.POST.get("execution_arguments", ""),
                                           userland_tracing=userland_tracing,
                                           enable_internet=enable_internet,
                                           additional_files=additional_files)

        if not status:
            return Response({"errors": True,
                             "error_msg": ret})
        else:
            context = ret
            LOG.debug(f"Execution context: {context}")
            start_analysis.delay(context)
            return Response({"submission_uuid": context["submission_uuid"]})


@api_view(["GET"])
def elf_reports(request, submission_uuid):
    """
    This function retrieves the analysis report of all ELFEN backends.

    :param request: API request from user to get report
    :type request: rest_framework.request.Request
    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :return: Analysis report
    :rtype: rest_framework.response.Response
    """
    if not submission_uuid:
        return Response({"errors": True,
                         "error_msg": "No submission UUID provided"})

    all_reports = get_all_reports(submission_uuid)
    if all_reports["console_output"]:
        # Console output may contain non-UTF-8 characters which causes UnicodeDecodeError
        # when requesting report through the API
        all_reports["console_output"] = str(all_reports["console_output"], "ISO-8859-1")

    return Response({"submission_uuid": submission_uuid, "report": all_reports})


@api_view(["GET"])
def elf_backend_report(request, submission_uuid, backend):
    """
    This function retrieves the analysis report of a given ELFEN backend
    for the given task.

    :param request: API request from user to get report for backend
    :type request: rest_framework.request.Request
    :param submission_uuid: Task UUID
    :type submission_uuid: str
    :param backend: ELFEN backend
    :type backend: str
    :return: Analysis report for backend
    :rtype: rest_framework.response.Response
    """
    if not submission_uuid:
        return Response({"errors": True,
                         "error_msg": "No submission UUID provided"})
    if not backend:
        return Response({"errors": True,
                         "error_msg": "No backend provided"})

    backend_report = get_backend_report(submission_uuid, backend)
    return Response({"submission_uuid": submission_uuid, "backend": backend,
                     "report": backend_report})
