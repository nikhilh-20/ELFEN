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
import uuid
import magic
import logging
import hashlib
from django.conf import settings
from web.enum import FileWriteStatus


logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def prep_file_submission(file, username, execution_time, machine,
                         execution_arguments, userland_tracing,
                         enable_internet, additional_files):
    """
    This function writes the main sample and additional files to disk.
    It then constructs a dictionary containing analysis options and metadata.

    :param file: Sample submitted by user
    :type file: django.core.files.uploadedfile.InMemoryUploadedFile
    :param username: Username of the user who submitted the sample
    :type username: str
    :param execution_time: Execution time for dynamic analysis
    :type execution_time: str
    :param machine: Machine to use for dynamic analysis
    :type machine: str
    :param execution_arguments: Execution arguments for dynamic analysis
    :type execution_arguments: str
    :param userland_tracing: Enable userland tracing for dynamic analysis
    :type userland_tracing: bool
    :param enable_internet: Enable internet access for dynamic analysis
    :type enable_internet: bool
    :param additional_files: Additional files submitted by user
    :type additional_files: list of django.core.files.uploadedfile.InMemoryUploadedFile
    :return: Status of writing file to disk, error message | analysis context
    :rtype: bool, dict
    """
    submission_uuid = str(uuid.uuid4())
    dirpath = os.path.join(settings.FILE_SUBMISSIONS_ROOT,
                           submission_uuid)
    LOG.debug(f"submission_uuid: {submission_uuid}, dirpath: {dirpath}, "
              f"filename: {file.name}, "
              f"len(additional files): {len(additional_files)}")

    # Write main file and any additional files to disk.
    # The analysis requires files on disk.
    status, hashes = write_submission_to_disk(main_file=file,
                                              dirpath=dirpath,
                                              additional_files=additional_files)

    if status == FileWriteStatus.ALREADY_EXISTS:
        LOG.error(f"Error writing files to disk: Duplicate directory: {dirpath}")
        return False, {"error_msg": "Error writing file to disk: Duplicate directory"}
    elif status == FileWriteStatus.ERROR:
        LOG.error(f"Error writing files to disk: {dirpath}")
        return False, {"error_msg": "Error writing file to disk"}
    # New successful submission
    elif status == FileWriteStatus.SUCCESS:
        LOG.debug(f"Successfully wrote files to disk: {dirpath}")
        additional_files_names = [f.name for f in additional_files]
        context = {
            "submission_uuid": submission_uuid,
            "username": username,
            "dirpath": dirpath,
            "file_hashes": hashes,
            "additional_files": additional_files_names,
            "machine": machine,
            "execution_time": execution_time,
            "execution_arguments": execution_arguments,
            "userland_tracing": userland_tracing,
            "enable_internet": enable_internet,
        }
        return True, context


def write_submission_to_disk(main_file, dirpath, additional_files=()):
    """
    This function writes the content of submitted files to dirpath directory.
    Each file is set as non-executable. The filename of the main sample is set
    to its SHA256 value. The filenames of additional files are set to their
    respective original filenames.

    :param main_file: This is the main file which will be analyzed.
    :type main_file: django.core.files.uploadedfile.InMemoryUploadedFile
    :param dirpath: Directory into which the files will be written into.
    :type dirpath: str
    :param additional_files: Any additional files to be submitted along with
                             the main file
    :type additional_files: list of django.core.files.uploadedfile.InMemoryUploadedFile
    :return: Status of write and hashes of main file.
    :rtype: bool, dict
    """
    hashes = {"md5": "", "sha1": "", "sha256": ""}
    # This would be a weird case where a duplicate directory already exists
    if os.path.isdir(dirpath):
        LOG.error(f"Directory already exists: {dirpath}")
        return FileWriteStatus.ALREADY_EXISTS, hashes

    # Create the directory
    os.mkdir(dirpath)

    # Calculate hashes of file in chunks. This will be the name of the main
    # file on disk.
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    for chunk in main_file.chunks():
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
    hashes["md5"] = md5.hexdigest()
    hashes["sha1"] = sha1.hexdigest()
    hashes["sha256"] = sha256.hexdigest()
    fpath = os.path.join(dirpath, hashes["sha256"])

    LOG.debug(f"Writing main sample to {fpath}")
    with open(fpath, "wb+") as f:
        # Reading in chunks to not overwhelm memory. I wonder if there's a way
        # to combine this and the above block. Reading the file twice is slow.
        for chunk in main_file.chunks():
            f.write(chunk)
    # Set sample to non-executable
    os.chmod(fpath, 0o444)

    try:
        file_magic = magic.from_file(fpath)
    except magic.MagicException:
        # Haven't looked into this too much. This exception is thrown when the
        # input is a severely truncated ELF binary. Weirdly, magic.from_file()
        # works fine in IPython
        with open(fpath, "rb") as f:
            file_magic = magic.from_buffer(f.read(4))

    if file_magic and (not file_magic.startswith("ELF") or "core file" in file_magic):
        LOG.error(f"Unsupported filetype: {file_magic}. Main sample cannot be "
                  f"analyzed by ELFEN. Deleting...")
        os.remove(fpath)
        os.rmdir(dirpath)
        return FileWriteStatus.ERROR, hashes

    for file in additional_files:
        # Writing to the file as named by the user. Sometimes, names are relevant.
        fpath = os.path.join(dirpath, file.name)
        LOG.debug(f"Writing additional sample to {fpath}")
        with open(fpath, "wb+") as f:
            # Reading in chunks to not overwhelm memory
            for chunk in file.chunks():
                f.write(chunk)
        # Set file to non-executable
        os.chmod(fpath, 0o444)

    return FileWriteStatus.SUCCESS, hashes
