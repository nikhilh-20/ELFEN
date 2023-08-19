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
from celery import shared_task
from web.models import SampleMetadata
from analysis.models import TaskMetadata
from analysis.tasks import start_hardcore_analysis

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def get_my_tasks_info():
    """
    This function retrieves the latest N tasks analyzed by ELFEN.
    This data is used to populate the ELFEN home page.

    :return: Information about the latest N tasks.
    :rtype: list of dict
    """
    top_n = [t for t in TaskMetadata.objects.all().order_by("-start_time")][:20]

    info = []
    for t in top_n:
        uuid = t.uuid
        start_time = t.start_time.strftime("%m/%d/%Y %H-%M-%S")
        end_time = t.end_time.strftime("%m/%d/%Y %H-%M-%S")
        sha256 = t.sha256.sha256
        info.append({
            "uuid": uuid, "start_time": start_time,
            "end_time": end_time, "sha256": sha256
        })

    return info


@shared_task(queue="submission")
def start_analysis(context):
    """
    This function begins analysis with the first step: extract sample
    metadata and dump it into elfen_db. Then it enters the main analysis
    pipeline.

    :param context: A dictionary containing username, user-submitted form
                    parameters and other analysis options/metadata.
    :type context: dict
    :return: None
    :rtype: None
    """
    LOG.debug("Creating SampleMetadata object")

    sample, _ = SampleMetadata.objects.get_or_create(sha256=context["file_hashes"]["sha256"])
    sample.username = context["username"]
    sample.md5 = context["file_hashes"]["md5"]
    sample.sha1 = context["file_hashes"]["sha1"]
    sample.save(update_fields=["username", "md5", "sha1"])

    start_hardcore_analysis(sample, context)
