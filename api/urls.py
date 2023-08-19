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

from django.urls import path
from django.shortcuts import redirect

from api import views

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path("submit/", lambda req: redirect("/api/submit/file")),
    path("submit/file", views.submit_elf, name="submit_elf_api"),
    path("report/file/<str:submission_uuid>/", views.elf_reports, name="report_api"),
    path("report/file/<str:submission_uuid>/<str:backend>/", views.elf_backend_report),
    path("token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
