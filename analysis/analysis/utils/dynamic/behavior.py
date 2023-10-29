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
import signal
import logging
import zipfile
import subprocess
from random import choice
from string import ascii_letters
from django.conf import settings

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def get_arch_image_zip(arch, endian, enable_internet):
    """
    Based on the given arch, this function retrieves a clean Linux sandbox
    image ZIP.

    :param arch: Architecture of submitted sample.
    :type arch: str
    :param endian: Endianness of submitted sample.
    :type endian: str
    :param enable_internet: Whether internet access is enabled for dynamic analysis
    :type enable_internet: bool
    :return: Path to the sandbox image ZIP, error message if any
    :rtype: str|None, str
    """
    arch = arch.lower()

    if "amd64" in arch or "i386" in arch:
        if enable_internet:
            image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                     "x8664", "image_net.zip")
        else:
            image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                     "x8664", "image.zip")
    elif arch == "arm":
        if endian == "le":
            if enable_internet:
                image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                         "arm", "image_net.zip")
            else:
                image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                         "arm", "image.zip")
        else:
            return None, f"Unsupported endianness for dynamic analysis: {endian}"
    elif arch == "ppc":
        if enable_internet:
            image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                     "ppc", "image_net.zip")
        else:
            image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                     "ppc", "image.zip")
    elif arch == "mips":
        if endian == "be":
            # Big endian
            if enable_internet:
                image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                         "mips", "image_net.zip")
            else:
                image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                         "mips", "image.zip")
        elif endian == "le":
            # Little endian
            if enable_internet:
                image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                         "mipsel", "image_net.zip")
            else:
                image_zip = os.path.join(settings.BASE_DIR, "rsrc", "ELFEN_images", "images",
                                         "mipsel", "image.zip")
        else:
            return None, f"Unsupported endianness for dynamic analysis: {endian}"
    else:
        return None, f"Unsupported architecture for dynamic analysis: {arch}"

    return image_zip, ""


def get_image_info(arch, endian, enable_internet):
    """
    Based on the given arch, this function retrieves a clean Linux sandbox
    image ZIP. It then unzips the kernel and root filesystem image,
    writes them to disk and returns the full path to it.

    :param arch: Architecture of submitted sample.
    :type arch: str
    :param endian: Endianness of submitted sample.
    :type endian: str
    :param enable_internet: Whether internet access is enabled for dynamic analysis
    :type enable_internet: bool
    :return: Dict containing sandbox image-related filepaths.
    :rtype: dict
    """
    LOG.debug(f"Getting sandbox image for architecture: {arch}")
    ret = {}

    arch = arch.lower()
    endian = endian.lower()

    if arch:
        image_zip, err_msg = get_arch_image_zip(arch, endian, enable_internet)
        if image_zip is None:
            ret["msg"] = err_msg
            return ret
    else:
        ret["msg"] = "Unknown architecture for dynamic analysis"
        return ret

    LOG.debug(f"Using sandbox image zip: {image_zip}")
    tmpdir = os.path.join("/tmp", "".join(choice(ascii_letters) for i in range(8)))
    with zipfile.ZipFile(image_zip, "r") as zip_ref:
        zip_ref.extractall(tmpdir, pwd=b"elfensandboximage")
    if "amd64" in arch or "i386" in arch:
        ret.update({
            "tmpdir": tmpdir,
            "kernel": os.path.join(tmpdir, "bzImage"),
            "filesystem": os.path.join(tmpdir, "rootfs.ext2"),
        })
    elif arch == "arm":
        ret.update({
            "tmpdir": tmpdir,
            # "kernel": os.path.join(tmpdir, "Image"),
            "kernel": os.path.join(tmpdir, "zImage"),
            "dtb": os.path.join(tmpdir, "versatile-pb.dtb"),
            "filesystem": os.path.join(tmpdir, "rootfs.ext2"),
        })
    elif arch == "mips":
        ret.update({
            "tmpdir": tmpdir,
            "kernel": os.path.join(tmpdir, "vmlinux"),
            "filesystem": os.path.join(tmpdir, "rootfs.ext2"),
        })
    elif arch == "ppc":
        ret.update({
            "tmpdir": tmpdir,
            "kernel": os.path.join(tmpdir, "uImage"),
            "filesystem": os.path.join(tmpdir, "rootfs.ext2"),
        })
    return ret


def get_qemu_cmd(arch, endian, dynamic_analysis_dir, enable_internet, linux_image_info):
    """
    Constructs the QEMU command-line string based on the given arguments.

    :param arch: Architecture of submitted sample
    :type arch: str
    :param endian: Endianness of submitted sample
    :type endian: str
    :param dynamic_analysis_dir: Host path where dynamic analysis artifacts
                                 will be stored
    :type dynamic_analysis_dir: str
    :param enable_internet: Whether internet access is enabled for dynamic analysis
    :type enable_internet: bool
    :param linux_image_info: Dictionary containing details about sandbox image
    :type linux_image_info: dict
    :return: QEMU command-line string
    :rtype: str|None
    """
    arch = arch.lower()
    endian = endian.lower()

    if "amd64" in arch or "i386" in arch:
        kernel = linux_image_info["kernel"]
        root_filesystem = linux_image_info["filesystem"]
        qemu_cmd = f"qemu-system-x86_64 -M pc -m 512 -kernel {kernel} " \
                   f"-drive format=raw,if=virtio,file={root_filesystem} " \
                   '-append "root=/dev/vda console=ttyS0" ' \
                   f"-fsdev local,path={dynamic_analysis_dir},security_model=mapped-xattr,id=guild " \
                   "-device virtio-9p-pci,fsdev=guild,mount_tag=guild -nographic"
    elif arch == "arm":
        dtb = linux_image_info.get("dtb")
        if dtb is None:
            return None
        kernel = linux_image_info["kernel"]
        root_filesystem = linux_image_info["filesystem"]
        if enable_internet:
            qemu_cmd = f"qemu-system-arm -M versatilepb -m 256 -kernel {kernel} -dtb {dtb} " \
                       f"-drive file={root_filesystem},if=scsi,format=raw " \
                       '-append "root=/dev/sda console=ttyAMA0,115200" -nographic ' \
                       f"-fsdev local,path={dynamic_analysis_dir},security_model=mapped-xattr,id=guild " \
                       "-netdev user,id=unet -device driver=virtio-net,netdev=unet " \
                       "-device virtio-9p-pci,fsdev=guild,mount_tag=guild"
        else:
            qemu_cmd = f"qemu-system-arm -M versatilepb -m 256 -kernel {kernel} -dtb {dtb} " \
                       f"-drive file={root_filesystem},if=scsi,format=raw " \
                       '-append "root=/dev/sda console=ttyAMA0,115200" -nographic ' \
                       f"-fsdev local,path={dynamic_analysis_dir},security_model=mapped-xattr,id=guild " \
                       "-device virtio-9p-pci,fsdev=guild,mount_tag=guild"
    elif arch == "mips":
        endian = endian.lower()
        kernel = linux_image_info["kernel"]
        root_filesystem = linux_image_info["filesystem"]

        if endian == "be":
            # Big endian
            qemu_cmd = f"qemu-system-mips -M malta -m 512 -kernel {kernel} " \
                       f"-drive format=raw,file={root_filesystem} " \
                       '-append "root=/dev/sda" ' \
                       f"-fsdev local,path={dynamic_analysis_dir},security_model=mapped-xattr,id=guild " \
                       "-device virtio-9p-pci,fsdev=guild,mount_tag=guild -nographic"
        else:
            # Little endian
            qemu_cmd = f"qemu-system-mipsel -M malta -m 512 -kernel {kernel} " \
                       f"-drive format=raw,file={root_filesystem} " \
                       '-append "root=/dev/sda" ' \
                       f"-fsdev local,path={dynamic_analysis_dir},security_model=mapped-xattr,id=guild " \
                       "-device virtio-9p-pci,fsdev=guild,mount_tag=guild -nographic"
    elif arch == "ppc":
        kernel = linux_image_info["kernel"]
        root_filesystem = linux_image_info["filesystem"]
        qemu_cmd = f"qemu-system-ppc -M ppce500 -cpu e500mc -m 256 -kernel {kernel} " \
                   f"-drive if=virtio,format=raw,file={root_filesystem} " \
                   '-append "root=/dev/vda console=ttyS0"  ' \
                   f"-fsdev local,path={dynamic_analysis_dir},security_model=mapped-xattr,id=guild " \
                   "-device virtio-9p-pci,fsdev=guild,mount_tag=guild -nographic"
    else:
        LOG.error("Unknown architecture. QEMU command not known.")
        return None

    return qemu_cmd


def deploy_qemu(polling_interval, exec_time, arch, endian, dynamic_analysis_dir,
                enable_internet, linux_image_info):
    """
    Deploys QEMU-based sandbox for the given sample.

    :param polling_interval: Time to wait before killing QEMU VM
    :type polling_interval: int
    :param exec_time: Execution time of the sample
    :type exec_time: int
    :param arch: Architecture of submitted sample
    :type arch: str
    :param endian: Endianness of submitted sample
    :type endian: str
    :param dynamic_analysis_dir: Host path where dynamic analysis artifacts
                                 will be stored
    :type dynamic_analysis_dir: str
    :param enable_internet: Whether internet access is enabled for dynamic analysis
    :type enable_internet: bool
    :param linux_image_info: Dictionary containing details about sandbox image
    :type linux_image_info: dict
    :return: Status of QEMU execution
    :rtype: bool
    """
    LOG.debug(f"Deploying QEMU VM for architecture: {arch}")
    if (linux_image_info.get("kernel") is None or
            linux_image_info.get("filesystem") is None):
        return None

    qemu_cmd = get_qemu_cmd(arch, endian, dynamic_analysis_dir, enable_internet, linux_image_info)

    if qemu_cmd:
        try:
            LOG.debug(f"QEMU command: {qemu_cmd}")
            # Call preexec_fn=os.setsid to run the child process in a new
            # process group. This will make it a session leader. This will
            # allow us to kill all processes in the process group with
            # os.killpg(), if needed.
            proc = subprocess.Popen(qemu_cmd, shell=True, preexec_fn=os.setsid)
            parent_pid = proc.pid
            LOG.debug(f"QEMU process PID: {parent_pid}")
            # There is ~6s setup before the sample actually starts running
            time.sleep(exec_time+6)
            # Poll for 10 times to check if the process is still running.
            num_polled = 0
            while proc.poll() is None and num_polled < 10:
                # Child process is still running. Sleep for a while and
                # check again
                time.sleep(polling_interval)
                num_polled += 1

            if proc.poll() is None:
                # Kill parent process and child process. This will kill all qemu
                # related processes. They will be in the same process group, so
                # os.killpg() should work.
                LOG.debug(f"Killing QEMU process with PID: {parent_pid}")
                os.killpg(parent_pid, signal.SIGTERM)

            LOG.debug(f"QEMU process exited with code: {proc.returncode}")
        except subprocess.CalledProcessError as err:
            LOG.debug(f"QEMU process couldn't be started/monitored: {err}")
            return None

    return True
