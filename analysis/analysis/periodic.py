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
import shutil
import logging

from random import choice
from celery import shared_task
from string import ascii_letters
from psycopg2.errors import UndefinedTable

from web.models import SampleMetadata
from analysis.analysis.utils.periodic.hac_lib import hac_resetDistCalc, HAC_T

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def hac_t_cluster(objs):
    """
    Given a list of sample objects, perform TLSH-based HAC-T clustering.

    :param objs: List of sample objects
    :type objs: list of web.models.SampleMetadata
    :return: List of cluster labels where -1 == unclustered
    :rtype: list of int
    """
    csv_content = ["sha256_hash,tlsh,signature"]

    tmpdir = os.path.join("/tmp", "".join(choice(ascii_letters)
                                          for _ in range(8)))
    os.mkdir(tmpdir)
    # csv_fpath will contain the data that is required for TLSH clustering code
    csv_fpath = os.path.join(tmpdir, "tlsh_input.csv")
    if os.path.isfile(csv_fpath):
        LOG.error(f"{csv_fpath} exists. Duplicate path. Aborting clustering")
        return None

    for obj in objs:
        sha256 = obj.sha256
        tlsh = obj.tlsh
        csv_content.append(f"{sha256},{tlsh},")

    with open(csv_fpath, "w") as f:
        f.write("\n".join(csv_content))

    # Perform TLSH-based HAC-T clustering
    hac_resetDistCalc()
    # res is a list of integer labels where -1 == unclustered
    # Two samples having the same label belong to the same cluster
    labels = HAC_T(csv_fpath, CDist=30)

    # Delete the temporary directory
    if os.path.isdir(tmpdir):
        shutil.rmtree(tmpdir)

    return labels


def apply_tlsh_clustering():
    LOG.debug("Clustering started")

    try:
        objs = SampleMetadata.objects.all()
    except UndefinedTable:
        LOG.debug("No sample objects found. Skipping clustering")
        return

    labels = hac_t_cluster(objs)

    for obj, label_ in zip(objs, labels):
        obj.similar = [objs[i].sha256
                       for i, label in enumerate(labels)
                       if label_ != -1 and label == label_]
        obj.save(update_fields=["similar"])

    LOG.debug("TLSH clustering complete")


@shared_task(queue="periodic_analysis")
def start_analysis():
    """
    This task is called by celery periodically to perform analyses such as
    clustering.

    :return: None
    :rtype: None
    """
    LOG.debug("Starting periodic analysis")

    apply_tlsh_clustering()
