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

from django.urls import path, include
from django.shortcuts import redirect

from web import views

urlpatterns = [
    path("", views.index, name="home"),
    path("", include("django.contrib.auth.urls")),
    path("register/", views.sign_up, name="register"),
    path("submit/", lambda req: redirect("/web/submit/file")),
    path("submit/file", views.submit_elf, name="submit_elf"),
    path("report/file/<str:submission_uuid>/", views.elf_reports, name="report"),
    path("report/file/<str:submission_uuid>/<str:backend>/", views.elf_backend_report,
         name="backend_report"),
    path("report/file/<str:submission_uuid>/<str:backend>/download/", views.download,
         name="artifact_download"),
]

handler404 = "web.views.not_found"
