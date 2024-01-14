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

import os
import logging
from django.http import HttpResponse, FileResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login
from web.forms import FileSubmissionForm, RegistrationForm
from django.contrib.auth.decorators import login_required
from web.utils import prep_file_submission
from web.tasks import start_analysis, get_my_tasks_info
from analysis.reporting.report import get_backend_report, get_all_reports, download_artifact


logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def index(request):
    """
    This function is called when a user visits the homepage of ELFEN.

    :param request: WSGIRequest
    :type request: django.core.handlers.wsgi.WSGIRequest
    :return: HTTP response
    :rtype: django.http.response.HttpResponse
    """
    tasks_info = get_my_tasks_info()
    LOG.debug("Index view called")
    return render(request, "web/home.html", {"recent_tasks": tasks_info})


def sign_up(request):
    """
    This function is called when a user wants to create a new account in ELFEN.

    :param request: WSGIRequest
    :type request: django.core.handlers.wsgi.WSGIRequest
    :return: HTTP response
    :rtype: django.http.response.HttpResponse
    """
    LOG.debug("Sign up view called")
    form = RegistrationForm()

    password_tips = form.fields.get("password1", "").help_text.split("\n")

    if request.method == "POST":
        LOG.debug("POST request received to sign up")
        form = RegistrationForm(request.POST)
        if form.is_valid():
            LOG.debug("POST request received to sign up is valid")
            user = form.save()
            login(request, user)
            return redirect("home")

    return render(request, "registration/sign_up.html", {"form": form,
                                                         "password_tips": password_tips})


@login_required
def submit_elf(request):
    """
    This function accepts file uploads from users and asynchronously
    starts analysis.

    :param request: WSGIRequest
    :type request: django.core.handlers.wsgi.WSGIRequest
    :return: HTTP response
    :rtype: django.http.response.HttpResponse
    """
    LOG.debug("Submit ELF view called")
    form = FileSubmissionForm()

    if request.method == "POST":
        LOG.debug("POST request received to submit ELF")
        form = FileSubmissionForm(request.POST, request.FILES)

        # Only authenticated users submitting valid forms are allowed
        if form.is_valid():
            LOG.debug("POST request received to submit ELF is valid")
            file = request.FILES["file"]
            additional_files = request.FILES.getlist("additional_files")
            userland_tracing = True if request.POST.get("userland_tracing", None) else False
            enable_internet = True if request.POST.get("enable_internet", None) else False
            exec_args = request.POST.get("execution_arguments", "")
            status, ret = prep_file_submission(file, request.user.username,
                                               request.POST["execution_time"],
                                               request.POST.get("machine"),
                                               execution_arguments=exec_args,
                                               userland_tracing=userland_tracing,
                                               enable_internet=enable_internet,
                                               additional_files=additional_files)

            if status is False:
                # TODO: Prepare error page if writing sample to disk fails
                return HttpResponse(ret["error_msg"])
            elif status is True:
                context = ret
                LOG.debug(f"Execution context: {context}")
                start_analysis.delay(context)
                return redirect("report", context["submission_uuid"])

    return render(request, "web/submit_elf.html", {"form": form})


def elf_reports(request, submission_uuid):
    """
    This function returns the analysis report for a given task UUID.

    :param request: WSGIRequest
    :type request: django.core.handlers.wsgi.WSGIRequest
    :param submission_uuid: Submission (aka task) UUID
    :type submission_uuid: str
    :return: HTTP response
    :rtype: django.http.response.HttpResponse
    """
    all_reports = get_all_reports(submission_uuid, web=True)

    if all_reports is None:
        context = {
            "msg": f"Task UUID: {submission_uuid} not found. You may have to "
                   "wait for a few seconds until the task is registered in the database. "
                   "Refresh the page to check again."
        }
        return render(request, "web/404.html", context=context, status=404)

    return render(request, "web/report_file.html", all_reports)


def elf_backend_report(request, submission_uuid, backend):
    """
    This function returns the analysis report for a given backend for a
    given task UUID.

    :param request: WSGIRequest
    :type request: django.core.handlers.wsgi.WSGIRequest
    :param submission_uuid: Submission (aka task) UUID
    :type submission_uuid: str
    :param backend: ELFEN backend name
    :type backend: str
    :return: HTTP response
    :rtype: django.http.response.HttpResponse
    """
    report = get_backend_report(submission_uuid, backend)

    context = {
        "submission_uuid": submission_uuid,
        "backend": backend,
        "report": report
    }

    return render(request, "web/report_backend.html", context)


def not_found(request, exception):
    return render(request, "web/404.html", status=404)


def download(request, submission_uuid, backend):
    """
    This function downloads the artifact for a given backend for a
    given task UUID.

    :param request: WSGIRequest
    :type request: django.core.handlers.wsgi.WSGIRequest
    :param submission_uuid: Submission (aka task) UUID
    :type submission_uuid: str
    :param backend: ELFEN backend name
    :type backend: str
    :return: Artifact file or HTTP response
    :rtype: django.http.response.FileResponse or django.http.response.HttpResponse
    """
    fd = download_artifact(submission_uuid, backend)

    if fd:
        return FileResponse(fd, as_attachment=True)

    return render(request, "web/404.html", status=404)
