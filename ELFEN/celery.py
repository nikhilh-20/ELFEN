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
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ELFEN.settings")
app = Celery("ELFEN")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks([
    "analysis.analysis.static",
    "analysis.analysis.dynamic",
    "analysis.detection.detection"
])
