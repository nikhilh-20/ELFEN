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
import random
import string
import logging
import subprocess

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def _gen_random_volume_name():
    """
    Generate UUID of format [0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}

    :return: Random Volume ID
    :rtype: str
    """
    LOG.debug("Generating random volume ID")
    return "".join(random.choices(string.hexdigits, k=8)).lower() + "-" + \
           "".join(random.choices(string.hexdigits, k=8)).lower() + "-" + \
           "".join(random.choices(string.hexdigits, k=4)).lower() + "-" + \
           "".join(random.choices(string.hexdigits, k=12)).lower()


def _gen_random_uuid():
    """
    Generate UUID of format ([0-9a-f]{2} ){16}

    :return: Random UUID
    :rtype: str
    """
    LOG.debug("Generating random UUID")
    random_uuid = uuid.uuid4().hex
    return " ".join([f"{random_uuid[i: i+2]}" for i in range(0, len(random_uuid), 2)])


def _get_c_code(vm_name, random_uuid, volume_id):
    """
    Generate C code to be compiled and executed. This is the source code for
    the esxcli binary.

    :param vm_name: Name of VM to be created
    :type vm_name: str
    :param random_uuid: Random UUID to be used
    :type random_uuid: str
    :param volume_id: Volume ID to be used
    :type volume_id: str
    :return: Source code for esxcli binary
    :rtype: str
    """
    LOG.debug("Constructing C code for esxcli binary")
    config_file = f"/vmfs/volumes/{volume_id}/{vm_name}/{vm_name}.vmx"

    src = "#include <stdio.h>\n"
    src += "#include <string.h>\n\n"

    src += "int main(int argc, char **argv)\n{\n"
    src += "\tchar *vm_process_list_output =\n"
    src += f"\t\t\"{vm_name}\\n\"\n"
    src += f"\t\t\"\\tWorld ID: {random.randint(1000000, 9999999)}\\n\"\n"
    src += f"\t\t\"\\tProcess ID: {random.randint(0, 100)}\\n\"\n"
    src += f"\t\t\"\\tVMX Cartel ID: {random.randint(1000000, 9999999)}\\n\"\n"
    src += f"\t\t\"\\tUUID: {random_uuid}\\n\"\n"
    src += f"\t\t\"\\tDisplay Name: {vm_name}\\n\"\n"
    src += f"\t\t\"\\tConfig File: {config_file}\";\n\n"

    src += "\tchar *storage_filesystem_list_output =\n"
    src += "\t\t\"Mount Point\\tVolume Name\\tUUID\\tMounted\\tType\\tSize\\tFree\\n\"\n"
    src += "\t\t\"-----------\\t-----------\\t----\\t-------\\t----\\t----\\t----\\n\"\n"
    src += f"\t\t\"/vmfs/volumes/{volume_id}\\t{volume_id}\\t{volume_id}\\ttrue\\tVMFS-6\\t"
    src += f"{random.randint(100000000000, 999999999999)}\\t{random.randint(100000000000, 999999999999)};\\n\";\n\n"

    src += "\tfor (int i = 1; i < argc; i++)\n\t{\n"
    src += "\t\tif (strcmp(argv[i], \"vm\") == 0 && i + 2 < argc && strcmp(argv[i+1], \"process\") == 0 && strcmp(argv[i+2], \"list\") == 0)\n"
    src += "\t\t{\n"
    src += "\t\t\tprintf(\"%s\\n\", vm_process_list_output);\n"
    src += "\t\t\treturn 0;\n"
    src += "\t\t}\n"
    src += "\t\telse if (strcmp(argv[i], \"storage\") == 0 && i + 2 < argc && strcmp(argv[i+1], \"filesystem\") == 0 && strcmp(argv[i+2], \"list\") == 0)\n"
    src += "\t\t{\n"
    src += "\t\t\tprintf(\"%s\\n\", storage_filesystem_list_output);\n"
    src += "\t\t\treturn 0;\n"
    src += "\t\t}\n"
    src += "\t}\n"
    src += "}"

    return src


def create_esxcli_binary(vm_name, random_uuid, volume_id, dynamic_analysis_dir):
    """
    This function creates the esxcli binary.

    :param vm_name: Name (randomized) of VM to be created
    :type vm_name: str
    :param random_uuid: Random UUID to be used
    :type random_uuid: str
    :param volume_id: Volume ID to be used
    :type volume_id: str
    :param dynamic_analysis_dir: Path to dynamic analysis directory
    :type dynamic_analysis_dir: str
    :return: Flag to indicate if compilation of esxcli binary was successful
    :rtype: bool
    """
    src_path = os.path.join(dynamic_analysis_dir, "esxcli.c")
    binary_path = os.path.join(dynamic_analysis_dir, "esxcli")
    src = _get_c_code(vm_name, random_uuid, volume_id)
    with open(src_path, "w") as f:
        f.write(src)

    try:
        LOG.debug(f"Compiling esxcli binary. Source path: {src_path}")
        subprocess.run(["gcc", src_path, "-o", binary_path], check=True)
        os.remove(src_path)
    except subprocess.CalledProcessError:
        LOG.error(f"Could not compile esxcli binary. Source path: {src_path}")
        return False

    return True


def _get_vmx(vm_name, random_uuid):
    """
    Generate .vmx file for VM.

    :param vm_name: Name of VM to be created
    :type vm_name: str
    :param random_uuid: Random UUID to be used
    :type random_uuid: str
    :return: VMX file contents
    :rtype: str
    """
    LOG.debug("Constructing .vmx file contents")
    iso_name = "/tmp/" + "".join(random.choices(string.hexdigits, k=8)).lower() + ".iso"

    contents = """.encoding = \"windows-1252\"
config.version = "8"
virtualHW.version = "10"
vcpu.hotadd = "TRUE"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
sata0.present = "TRUE"
memsize = "2048"
mem.hotadd = "TRUE"
scsi0:0.present = "TRUE"
"""
    contents += f"scsi0:0.fileName = \"{vm_name}.vmdk\"\n"
    contents += "sata0:1.present = \"TRUE\"\n"
    contents += f"sata0:1.fileName = \"{iso_name}\"\n"
    contents += """sata0:1.deviceType = "cdrom-image"
usb.present = "TRUE"
ehci.present = "TRUE"
ehci.pciSlotNumber = "34"
sound.present = "TRUE"
sound.fileName = "-1"
sound.autodetect = "TRUE"
mks.enable3d = "TRUE"
serial0.present = "TRUE"
serial0.fileType = "thinprint"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
vmci0.present = "TRUE"
hpet0.present = "TRUE"
usb.vbluetooth.startConnected = "TRUE"
"""
    contents += f"displayName = \"{vm_name}\"\n"
    contents += "guestOS = \"ubuntu-64\"\n"
    contents += f"nvram = \"{vm_name}.nvram\"\n"
    contents += """virtualHW.productCompatibility = "hosted"
gui.exitOnCLIHLT = "FALSE"
powerType.powerOff = "soft"
powerType.powerOn = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"
"""
    contents += f"extendedConfigFile = \"{vm_name}.vmxf\"\n"
    contents += "floppy0.present = \"FALSE\"\n"
    contents += f"uuid.bios = \"{random_uuid}\"\n"
    contents += f"uuid.location = \"{random_uuid}\"\n"
    contents += """replay.supported = "FALSE"
replay.filename = ""
scsi0:0.redo = ""
pciBridge0.pciSlotNumber = "17"
pciBridge4.pciSlotNumber = "21"
pciBridge5.pciSlotNumber = "22"
pciBridge6.pciSlotNumber = "23"
pciBridge7.pciSlotNumber = "24"
scsi0.pciSlotNumber = "16"
usb.pciSlotNumber = "32"
sound.pciSlotNumber = "33"
vmci0.pciSlotNumber = "35"
sata0.pciSlotNumber = "36"
vmci0.id = "1437287217"
vmotion.checkpointFBSize = "134217728"
cleanShutdown = "TRUE"
softPowerOff = "TRUE"
usb:1.speed = "2"
usb:1.present = "TRUE"
usb:1.deviceType = "hub"
usb:1.port = "1"
usb:1.parent = "-1"
tools.remindInstall = "TRUE"
usb:0.present = "TRUE"
usb:0.deviceType = "hid"
usb:0.port = "0"
usb:0.parent = "-1"
"""
    return contents


def _get_vmxf(vm_name, random_uuid):
    """
    Generate .vmxf file for VM.

    :param vm_name: Name of VM to be created
    :type vm_name: str
    :param random_uuid: Random UUID to be used
    :type random_uuid: str
    :return: VMXF file contents
    :rtype: str
    """
    LOG.debug("Constructing .vmxf file contents")
    contents = """<?xml version="1.0"?>
<Foundry>
<VM>
"""
    contents += f"<VMId type=\"string\">{random_uuid}</VMId>\n"
    contents += """<ClientMetaData>
<clientMetaDataAttributes/>
<HistoryEventList/></ClientMetaData>
"""
    contents += f"<vmxPathName type=\"string\">{vm_name}.vmx</vmxPathName></VM></Foundry>\n"
    return contents


def create_supporting_esxcli_files(vm_name, random_uuid, dynamic_analysis_dir):
    """
    This function creates supporting ESXi VM files. These include .vmx, .vmxf,
     .vmdk and .nvram files.

    :param vm_name: Name of VM to be created
    :type vm_name: str
    :param random_uuid: Random UUID to be used for VM
    :type random_uuid: str
    :param dynamic_analysis_dir: Path to dynamic analysis directory
    :type dynamic_analysis_dir: str
    :return: None
    :rtype: None
    """
    LOG.debug("Constructing ESXi VM supporting files")
    vmx_path = os.path.join(dynamic_analysis_dir, vm_name + ".vmx")
    vmx_contents = _get_vmx(vm_name, random_uuid)
    with open(vmx_path, "w") as f:
        f.write(vmx_contents)

    vmxf_path = os.path.join(dynamic_analysis_dir, vm_name + ".vmxf")
    vmxf_contents = _get_vmxf(vm_name, random_uuid)
    with open(vmxf_path, "w") as f:
        f.write(vmxf_contents)

    # Large filesize to avoid evasion technique where malware checks filesize.
    vmdk_filesize = 512000
    vmdk_filepath = os.path.join(dynamic_analysis_dir, vm_name + ".vmdk")
    with open(vmdk_filepath, "wb") as f:
        # Prepend VMDK file signature
        f.write(b"\x4b\x44\x4d\x56" + os.urandom(vmdk_filesize))

    # Large filesize to avoid evasion technique where malware checks filesize.
    nvram_filesize = 8684
    nvram_filepath = os.path.join(dynamic_analysis_dir, vm_name + ".nvram")
    with open(nvram_filepath, "wb") as f:
        # Prepend NVRAM file signature
        f.write(b"\x4d\x52\x56\x4e" + os.urandom(nvram_filesize))


def create_esxcli_files(dynamic_analysis_dir):
    """
    This function creates ESXi-related files for dynamic analysis. Ransomware
    for ESXi will end up targeting these files.

    :param dynamic_analysis_dir: Dynamic analysis directory on disk.
    :return: Flag to indicate if ESXi-related files were written to disk.
    :rtype: bool
    """
    LOG.debug("Creating ESXi-related files")
    random_uuid = _gen_random_uuid()
    volume_id = _gen_random_volume_name()
    vm_name_length = random.randint(6, 16)
    vm_name = "".join(random.choices(string.ascii_letters, k=vm_name_length))

    status = create_esxcli_binary(vm_name, random_uuid, volume_id, dynamic_analysis_dir)
    if not status:
        LOG.error("Could not create esxcli binary")
        return False

    create_supporting_esxcli_files(vm_name, random_uuid, dynamic_analysis_dir)

    # Volume ID and VM name are required by the orchestrator to know where to
    # write ESXi files
    with open(os.path.join(dynamic_analysis_dir, "volume_id"), "w") as f:
        f.write(volume_id)
    with open(os.path.join(dynamic_analysis_dir, "vm_name"), "w") as f:
        f.write(vm_name)

    return True
