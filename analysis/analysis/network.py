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
import time
import logging
import datetime

from scapy.all import rdpcap
from scapy.layers.all import DNS
from celery import shared_task

from analysis.analysis.utils.network.dns_analysis import dns_analysis
from web.models import SampleMetadata
from analysis.models import TaskMetadata
from analysis.analysis_models.utils import TaskStatus
from analysis.analysis_models.network_analysis import NetworkAnalysisReports, \
     PcapAnalysis

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def perform_pcap_analysis(pcap_fpath, sample):
    """
    This function performs analysis on the given PCAP file.

    :param pcap_fpath: The path to the PCAP file generated during dynamic analysis.
    :type pcap_fpath: str
    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :return: PcapAnalysis object
    :rtype: analysis.analysis_models.network_analysis.PcapAnalysis
    """
    LOG.debug(f"Starting PCAP analysis on {pcap_fpath}")
    dns_packets = {}
    pcap_analysis = PcapAnalysis.objects.create(
        status=TaskStatus.IN_PROGRESS
    )

    packets = rdpcap(pcap_fpath)

    for packet in packets:
        if DNS in packet:
            tid = packet[DNS].id
            if tid not in dns_packets:
                dns_packets[tid] = []
            # Expectation: first the DNS query packet will reach this code, then
            # the DNS response packet
            dns_packets[tid].append(packet)

    if dns_packets:
        dns_analysis(dns_packets, sample, pcap_analysis)

    pcap_analysis.status = TaskStatus.COMPLETE
    pcap_analysis.save(update_fields=["status"])
    return pcap_analysis


@shared_task(queue="network_analysis")
def start_analysis(context):
    """
    This task is called by analysis.tasks, and it kicks off a series of network
    analysis steps.

    :param context: A dictionary containing username, user-submitted form
                    parameters and other analysis options/metadata.
    :type context: dict
    :return: None
    :rtype: None
    """
    sample_sha256 = context["file_hashes"]["sha256"]
    sample = SampleMetadata.objects.get(sha256=sample_sha256)
    dirpath = context["dirpath"]
    submission_id = context["submission_uuid"]
    parent_task = TaskMetadata.objects.get(uuid=submission_id)
    task_reports = parent_task.taskreports

    analysis_modules = context.get("config", {}).get("analysis", [])
    if not analysis_modules:
        LOG.error("No analysis module defined. No detection analysis will be performed.")
        return
    if "dynamic" not in analysis_modules:
        LOG.error("Dynamic analysis was not conducted. No network analysis will be performed.")
        task_reports.network_reports = NetworkAnalysisReports.objects.create(
            status=TaskStatus.NOT_STARTED,
        )
        task_reports.save(update_fields=["network_reports"])
        return
    if not context["enable_internet"]:
        LOG.warning("Internet not enabled in sandbox. No network analysis will be performed.")
        task_reports.network_reports = NetworkAnalysisReports.objects.create(
            status=TaskStatus.NOT_STARTED,
        )
        task_reports.save(update_fields=["network_reports"])
        return

    LOG.debug("Starting network analysis task")
    # Create NetworkAnalysisReports task object
    network_analysis_report = NetworkAnalysisReports.objects.create(
        status=TaskStatus.IN_PROGRESS,
    )
    LOG.debug(f"Created NetworkAnalysisReports object: {network_analysis_report}")
    task_reports.network_reports = network_analysis_report
    task_reports.save(update_fields=["network_reports"])
    LOG.debug(f"Updated TaskReports object: {task_reports} with "
              f"NetworkAnalysisReports object: {task_reports.network_reports}")

    # Wait until dynamic analysis is complete
    time_delta = 300
    execution_time = int(context["execution_time"])
    LOG.debug(f"Waiting for dynamic analysis report to complete")
    start_time = datetime.datetime.now()

    dynamic_reports = task_reports.dynamic_reports
    while dynamic_reports is None:
        task_reports.refresh_from_db()
        dynamic_reports = task_reports.dynamic_reports

    while dynamic_reports.status != TaskStatus.COMPLETE:
        time.sleep(10)
        dynamic_reports.refresh_from_db()
        if dynamic_reports.status == TaskStatus.ERROR:
            err_msg = "Dynamic analysis failed. No network analysis from it."
            LOG.error(err_msg)
            network_analysis_report.status = TaskStatus.ERROR
            network_analysis_report.save(update_fields=["status"])
            return
        if (datetime.datetime.now() - start_time).seconds > (execution_time + time_delta):
            err_msg = f"Dynamic analysis took too long to complete: >{execution_time + time_delta}s"
            LOG.error(err_msg)
            network_analysis_report.status = TaskStatus.ERROR
            network_analysis_report.save(update_fields=["status"])
            return

    # Artifacts of dynamic analysis will be stored here.
    dynamic_analysis_dir = os.path.join(dirpath, "dynamic_analysis")
    pcap_fpath = os.path.join(dynamic_analysis_dir, "capture.pcap")

    if not os.path.isfile(pcap_fpath):
        LOG.warning(f"Dynamic analysis did not produce a pcap file: {pcap_fpath}. "
                    "Network analysis cannot be performed.")
        network_analysis_report.status = TaskStatus.COMPLETE
        network_analysis_report.save(update_fields=["status"])
        return

    network_analysis_report.pcapanalysis = perform_pcap_analysis(pcap_fpath,
                                                                 sample)
    network_analysis_report.status = TaskStatus.COMPLETE
    network_analysis_report.save(update_fields=["pcapanalysis", "status"])

    LOG.debug(f"Network analysis task complete")
