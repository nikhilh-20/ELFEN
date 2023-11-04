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
import json
import time
import shutil
import pathlib
import zipfile
import logging
from random import choice
from celery import shared_task
from string import ascii_letters

from analysis.analysis.utils.dynamic.behavior import get_image_info, deploy_qemu,\
                                                     get_arch_endian_from_machine_name
from analysis.analysis.utils.dynamic.dynamic import analyze_trace
from analysis.analysis.utils.dynamic.esxcli_files import create_esxcli_files
from analysis.analysis_models.utils import TaskStatus
from analysis.analysis_models.dynamic_analysis import DynamicAnalysisReports
from analysis.models import TaskMetadata
from analysis.analysis_models.dynamic_analysis import MemoryStrings
from web.models import SampleMetadata
from analysis.analysis.utils.static.strings import get_sample_strings

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def apply_memstrings(sample, dynamic_analysis_dir):
    """
    This function applies strings on dynamic analysis artifacts, namely memory
    dump of relevant processes. It then updates the DB.

    :param sample: SampleMetadata object
    :type sample: web.models.SampleMetadata
    :param dynamic_analysis_dir: Host directory in which dynamic analysis
                                 artifacts are stored
    :type dynamic_analysis_dir: str
    :return: MemoryStrings object
    :rtype: analysis.analysis_models.dynamic_analysis.MemoryStrings
    """
    all_strings = []
    all_err_msg = []
    obj = MemoryStrings.objects.create(sample=sample,
                                       status=TaskStatus.IN_PROGRESS)

    # Extract memory dumps to this temp directory
    tmpdir = os.path.join("/tmp", "".join(choice(ascii_letters) for _ in range(8)))

    # Extract memory dumps and extract strings from them
    mem_dumps_zip = os.path.join(dynamic_analysis_dir, "memdump.zip")
    if os.path.isfile(mem_dumps_zip):
        with zipfile.ZipFile(mem_dumps_zip, "r") as zip_ref:
            zip_ref.extractall(tmpdir)

        for memdump_fname in os.listdir(tmpdir):
            memdump_path = os.path.join(tmpdir, memdump_fname)
            memdump_strings, err_msg = get_sample_strings(memdump_path)

            if err_msg:
                all_err_msg.append(err_msg)

            if memdump_strings is None:
                continue
            LOG.debug(f"Extracted {len(memdump_strings)} strings from {memdump_path}")

            all_strings.extend(memdump_strings)

        # Deduplicate
        all_strings = list(set(all_strings))
        all_err_msg = list(set(all_err_msg))
        if all_err_msg:
            obj.errors = True
            obj.error_msg = all_err_msg
            obj.save(update_fields=["errors", "error_msg"])

    if os.path.isdir(tmpdir):
        shutil.rmtree(tmpdir)

    # Write memory strings to disk
    if all_strings:
        with open(os.path.join(dynamic_analysis_dir, "memstrings.json"), "w") as f:
            json.dump({"memstrings": all_strings}, f)

    obj.strs = all_strings
    obj.status = TaskStatus.COMPLETE
    obj.save(update_fields=["strs", "status"])

    return obj


def apply_droppedfiles(dynamic_analysis_dir, dynamic_analysis_report):
    """
    This function extracts dropped files and updates the DB.

    :param dynamic_analysis_dir: Host directory in which dynamic analysis
                                 artifacts are stored
    :type dynamic_analysis_dir: str
    :param dynamic_analysis_report: DynamicAnalysisReports object
    :type dynamic_analysis_report: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    :return: None
    :rtype: None
    """
    # Extract dropped files to this temp directory
    tmpdir = os.path.join("/tmp", "".join(choice(ascii_letters) for _ in range(8)))
    dropped_files_zip = os.path.join(dynamic_analysis_dir, "dropped.zip")
    if os.path.isfile(dropped_files_zip):
        with zipfile.ZipFile(dropped_files_zip, "r") as zip_ref:
            zip_ref.extractall(tmpdir)

        dropped_files = [str(e).replace(f"{tmpdir}/", "")
                         for e in list(pathlib.Path(tmpdir).rglob("*")) if e.is_file()]
        dynamic_analysis_report.dropped_files = dropped_files
        dynamic_analysis_report.save(update_fields=["dropped_files"])

    # Delete tmpdir
    if os.path.isdir(tmpdir):
        shutil.rmtree(tmpdir)


def setup_sandbox_files(sample_path, additional_files, exec_args, exec_time,
                        userland_tracing, dirpath, dynamic_analysis_dir,
                        task_reports, dynamic_analysis_report):
    """
    This function sets up files required for dynamic analysis into the dynamic
    analysis directory on the host, where it'll be later picked up by the sandbox.

    :param sample_path: Path to the main sample
    :type sample_path: str
    :param additional_files: List of paths to dependencies of the main sample
    :type additional_files: list
    :param exec_args: Cmdline arguments to be passed to the main sample
    :type exec_args: str
    :param exec_time: Execution time of the sample
    :type exec_time: str
    :param userland_tracing: Whether userland tracing is enabled
    :type userland_tracing: bool
    :param dirpath: Host directory in which analysis-related files are stored
    :type dirpath: str
    :param dynamic_analysis_dir: Host directory in which dynamic analysis artifacts
                                 are stored
    :type dynamic_analysis_dir: str
    :param task_reports: TaskReports object
    :type task_reports: analysis.models.TaskReports
    :param dynamic_analysis_report: DynamicAnalysisReports object
    :type dynamic_analysis_report: analysis.analysis_models.dynamic_analysis.DynamicAnalysisReports
    :return: Status of setup
    :rtype: bool
    """
    # Copy sample and additional files into analysis directory.
    try:
        LOG.debug(f"Copying sample and additional files to {dynamic_analysis_dir}")
        shutil.copy(sample_path, os.path.join(dynamic_analysis_dir,
                                              "main_sample"))
        for f in additional_files:
            shutil.copy(os.path.join(dirpath, f), dynamic_analysis_dir)
    except PermissionError:
        err_msg = "Hit PermissionError when copying main sample and additional" \
                  "files into dynamic analysis directory"
        LOG.error(err_msg)
        dynamic_analysis_report.status = TaskStatus.ERROR
        dynamic_analysis_report.errors = True
        dynamic_analysis_report.error_msg = err_msg
        dynamic_analysis_report.save(update_fields=["status", "errors", "error_msg"])
        task_reports.status = TaskStatus.ERROR
        task_reports.error_msg += f"{err_msg},"
        task_reports.errors = True
        task_reports.save(update_fields=["status", "errors", "error_msg"])
        return False

    # Copy command-line execution arguments into a file. Command expansion will
    # be used to pass the file content as command-line arguments to the sample.
    # Something like: ./sample "$(< file.txt)"
    if exec_args:
        LOG.debug(f"Creating execution arguments file in {dynamic_analysis_dir}")
        with open(os.path.join(dynamic_analysis_dir, "exec_args"), "w") as f:
            f.write(exec_args)
    # Copy execution time into a file. This will be used to limit the execution
    # time of the sample.
    if exec_time:
        LOG.debug(f"Creating execution time file in {dynamic_analysis_dir}")
        with open(os.path.join(dynamic_analysis_dir, "timer"), "w") as f:
            f.write(exec_time)
    # Create a file whose presence will enable userland tracing of certain libc
    # functions.
    if userland_tracing:
        LOG.debug(f"Creating userland tracing file in {dynamic_analysis_dir}")
        with open(os.path.join(dynamic_analysis_dir, "prel0ad"), "w"):
            pass

    return True


@shared_task(queue="dynamic_analysis")
def start_analysis(context):
    """
    This task is called by analysis.tasks, and it kicks off a series of dynamic
    analysis steps.

    :param context: A dictionary containing username, user-submitted form
                    parameters and other analysis options/metadata.
    :type context: dict
    :return: None
    :rtype: None
    """
    LOG.debug("Starting dynamic analysis task")
    sample_sha256 = context["file_hashes"]["sha256"]
    sample = SampleMetadata.objects.get(sha256=sample_sha256)
    dirpath = context["dirpath"]
    submission_id = os.path.basename(os.path.normpath(dirpath))

    parent_task = TaskMetadata.objects.get(uuid=submission_id)
    LOG.debug(f"Got parent task: {parent_task} from TaskMetadata table")
    task_reports = parent_task.taskreports
    LOG.debug(f"Got TaskReports object: {task_reports} from TaskReports table")
    # Create DynamicAnalysisReports task object
    dynamic_analysis_report = DynamicAnalysisReports.objects.create(
        status=TaskStatus.IN_PROGRESS,
    )
    LOG.debug(f"Created DynamicAnalysisReports object: {dynamic_analysis_report}")
    task_reports.dynamic_reports = dynamic_analysis_report
    task_reports.save(update_fields=["dynamic_reports"])
    LOG.debug(f"Updated TaskReports object: {task_reports} with "
              f"DynamicAnalysisReports object: {task_reports.dynamic_reports}")

    additional_files = context["additional_files"]
    # Not checking if sample was fixed. For dynamic analysis, the only thing
    # that matters is if the sample can run on its own. If it's corrupted, it
    # should not run. Period. It should not be fixed and then executed because
    # that's not the *behavior* of the submitted sample.
    sample_path = context["sample_path"]
    machine = context["machine"]
    exec_args = context["execution_arguments"]
    exec_time = context["execution_time"]
    userland_tracing = context["userland_tracing"]
    enable_internet = context["enable_internet"]

    LOG.debug("Dynamic analysis context: "
              f"submission_id: {submission_id}, dirpath: {dirpath}, "
              f"sample_sha256={sample_sha256}, ",
              f"additional_files: {additional_files}, sample_path: {sample_path}, "
              f"machine: {machine}, exec_args: {exec_args}, exec_time: {exec_time}, "
              f"userland_tracing: {userland_tracing}, enable_internet: {enable_internet}")

    # Artifacts of dynamic analysis will be stored here.
    dynamic_analysis_dir = os.path.join(dirpath, "dynamic_analysis")
    os.mkdir(dynamic_analysis_dir)

    # Files required for dynamic analysis are copied into the dynamic analysis
    # directory on the host.
    status = setup_sandbox_files(sample_path, additional_files, exec_args,
                                 exec_time, userland_tracing, dirpath,
                                 dynamic_analysis_dir, task_reports,
                                 dynamic_analysis_report)
    if not status:
        return

    if machine == "auto":
        # Wait for static analysis to finish extracting sample features. This should
        # be fairly quick. One of these feature is the target architecture. Wait for
        # maximum of 10m (arbitrary threshold).
        LOG.debug(f"Waiting for static analysis to finish extracting sample features"
                  f"for submission_id: {submission_id}")
        samplefeatures = None
        start_wait = time.time()
        while time.time() - start_wait < 600:
            static_analysis_report = TaskMetadata.objects.get(uuid=submission_id).\
                                        taskreports.static_reports

            if (static_analysis_report and
                    static_analysis_report.samplefeatures is not None):
                samplefeatures = static_analysis_report.samplefeatures
                LOG.debug(f"Got samplefeatures: {samplefeatures} from "
                          f"StaticAnalysisReports table")
                break

            LOG.debug("Sleeping for 5s before checking again")
            time.sleep(5)

        if not samplefeatures:
            err_msg = "Could not determine architecture from static analysis"\
                      "Not going to guess target Linux arch and waste time. "\
                      "Skipping dynamic analysis."
            LOG.error(err_msg)
            dynamic_analysis_report.status = TaskStatus.ERROR
            dynamic_analysis_report.errors = True
            dynamic_analysis_report.error_msg = err_msg
            dynamic_analysis_report.save(update_fields=["status", "errors", "error_msg"])
            task_reports.status = TaskStatus.ERROR
            task_reports.error_msg += f"{err_msg},"
            task_reports.errors = True
            task_reports.save(update_fields=["status", "errors", "error_msg"])
            return

        # Derive arch, endian from extracted sample features
        arch = samplefeatures.arch
        endian = samplefeatures.endian
    else:
        # Get arch, endian as per user machine choice
        arch, endian = get_arch_endian_from_machine_name(machine)
    linux_image_info = get_image_info(arch, endian, enable_internet)
    if linux_image_info.get("msg", None):
        err_msg = linux_image_info["msg"]
        LOG.error(err_msg)
        dynamic_analysis_report.status = TaskStatus.ERROR
        dynamic_analysis_report.errors = True
        dynamic_analysis_report.error_msg = err_msg
        dynamic_analysis_report.save(update_fields=["status", "errors", "error_msg"])
        task_reports.status = TaskStatus.ERROR
        task_reports.error_msg += f"{err_msg},"
        task_reports.errors = True
        task_reports.save(update_fields=["status", "errors", "error_msg"])
        return
    LOG.debug(f"Sandbox image context: {linux_image_info}")

    status = create_esxcli_files(dynamic_analysis_dir)
    if not status:
        err_msg = "Failed to create dummy esxcli files"
        LOG.error(err_msg)
        dynamic_analysis_report.status = TaskStatus.ERROR
        dynamic_analysis_report.errors = True
        dynamic_analysis_report.error_msg = err_msg
        dynamic_analysis_report.save(update_fields=["status", "errors", "error_msg"])
        task_reports.status = TaskStatus.ERROR
        task_reports.error_msg += f"{err_msg},"
        task_reports.errors = True
        task_reports.save(update_fields=["status", "errors", "error_msg"])
        return

    status = deploy_qemu(15, int(exec_time), arch, endian, dynamic_analysis_dir,
                         enable_internet, linux_image_info)
    if not status:
        err_msg = "Failed to deploy QEMU"
        LOG.error(err_msg)
        dynamic_analysis_report.status = TaskStatus.ERROR
        dynamic_analysis_report.errors = True
        dynamic_analysis_report.error_msg = err_msg
        dynamic_analysis_report.save(update_fields=["status", "errors", "error_msg"])
        task_reports.status = TaskStatus.ERROR
        task_reports.error_msg += f"{err_msg},"
        task_reports.errors = True
        task_reports.save(update_fields=["status", "errors", "error_msg"])
        return
    LOG.debug("QEMU analysis complete")

    # Record command-line
    try:
        with open(os.path.join(dynamic_analysis_dir, "filename"), "r") as f:
            sample_filename = f.read().strip()
    except FileNotFoundError:
        sample_filename = ""
    cmdline = f"./{sample_filename} {exec_args}"
    parent_task.cmdline = cmdline
    parent_task.save(update_fields=["cmdline"])

    memdump_zip = os.path.join(dynamic_analysis_dir, "memdump.zip")
    if os.path.isfile(memdump_zip):
        dynamic_analysis_report.memdump = True
        dynamic_analysis_report.save(update_fields=["memdump"])

    # Extract dropped files, if any
    apply_droppedfiles(dynamic_analysis_dir, dynamic_analysis_report)

    # Extract memory strings from memory dumps, if any
    memstrings = apply_memstrings(sample, dynamic_analysis_dir)
    dynamic_analysis_report.memstrings = memstrings
    dynamic_analysis_report.save(update_fields=["memstrings"])

    dynamic_analysis_report = analyze_trace(sample, endian, dynamic_analysis_dir,
                                            task_reports)

    if dynamic_analysis_report:
        dynamic_analysis_report.status = TaskStatus.COMPLETE
        dynamic_analysis_report.save(update_fields=["status"])
    else:
        err_msg = "No dynamic analysis report object. Something went wrong "\
                  "while analyzing trace logs."
        LOG.error(err_msg)
        task_reports.status = TaskStatus.ERROR
        task_reports.error_msg += f"{err_msg},"
        task_reports.errors = True
        task_reports.save(update_fields=["status", "errors", "error_msg"])

    LOG.debug(f"Deleting image directory: {linux_image_info['tmpdir']}")
    shutil.rmtree(linux_image_info["tmpdir"])
    LOG.debug(f"Dynamic analysis complete")
