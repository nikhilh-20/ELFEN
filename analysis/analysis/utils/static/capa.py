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
import struct
from django.conf import settings

import capa.main
import capa.rules
import capa.exceptions
import capa.render.json
from envi.exc import EnviException


def capa_details(rules_path, sigs_path, file_path):
    """
    Adopted from https://github.com/mandiant/capa/blob/master/scripts/capa_as_library.py.

    :param rules_path: Full on-disk path to capa rules directory.
    :type rules_path: str
    :param sigs_path: Full on-disk path to capa sigs directory.
    :type sigs_path: str
    :param file_path: Full on-disk path to the sample.
    :type file_path: str
    :return: capa report JSON.
    :rtype: dict
    """
    err_msg = ""
    # load rules from disk
    rules = capa.main.get_rules([rules_path])

    # load sigs from disk
    sigs = capa.main.get_signatures(sigs_path)

    try:
        # extract features and find capabilities
        extractor = capa.main.get_extractor(path=file_path, format_="elf",
                                            os_="linux", backend=capa.main.BACKEND_VIV,
                                            sigpaths=sigs, disable_progress=True)
    except capa.exceptions.UnsupportedOSError:
        err_msg = "CAPA does not support the OS"
        # Packed programs may cause this error. capa is not great against packing.
        return None, err_msg
    except capa.exceptions.UnsupportedArchError:
        err_msg = "CAPA does not support the architecture"
        # Packed programs may cause this error. capa is not great against packing.
        return None, err_msg
    except (EnviException, struct.error, UnicodeDecodeError) as err:
        return None, str(err)
    except Exception as err:
        return None, str(err)

    capabilities, counts = capa.main.find_capabilities(rules, extractor,
                                                       disable_progress=True)

    # collect metadata (used only to make rendering more complete)
    meta = capa.main.collect_metadata([], file_path,  format_="elf", os_="linux",
                                      rules_path=[rules_path], extractor=extractor)
    meta["analysis"].update(counts)
    meta["analysis"]["layout"] = capa.main.compute_layout(rules, extractor,
                                                          capabilities)

    return json.loads(capa.render.json.render(meta, rules,
                                              capabilities)), err_msg


def get_capa_capabilities(sample_path):
    """
    This function applies FLARE CAPA (https://github.com/mandiant/capa)
    on the sample. It leverages https://pypi.org/project/flare-capa.

    :param sample_path: The full on-disk path to the sample
    :type sample_path: str
    :return: Base address at which capa loaded the sample,
             matched capa rules, namespaces, addresses, error message, if any.
    :rtype: int, list of str, list of str, list of lists of int, str
    """
    capa_path = os.path.join(settings.BASE_DIR, "rsrc", "capa")
    rules_path = os.path.join(capa_path, "rules")
    sigs_path = os.path.join(capa_path, "sigs")
    capa_output, err_msg = capa_details(rules_path, sigs_path, sample_path)

    if capa_output is None:
        # Error in capa capabilities extraction
        return None, None, None, None, err_msg

    base_address_deets = capa_output["meta"]["analysis"]["base_address"]
    # base_address_deets contains two keys: "type" and "value".
    # I think "absolute" (type AbsoluteVirtualAddress) is the only active base
    # address type. If not, TODO I need to update this code.
    # if base_address_deets["type"].lower() == "absolute":
    base_address = base_address_deets["value"]

    rule_names = []
    rule_namespaces = []
    rule_match_addrs = []
    for rule, rule_deets in capa_output["rules"].items():
        meta_deets = rule_deets["meta"]
        if meta_deets["lib"]:
            continue
        rule_names.append(meta_deets["name"])
        rule_namespaces.append(meta_deets["namespace"])

        match_values = set()
        for match_ in rule_deets["matches"]:
            for entry in match_:
                # There is one specific entry that I need to look at
                # Has the semantic: {"type": "...", "value": ...}
                if set(entry.keys()) == {"type", "value"}:
                    # I think "absolute" (type AbsoluteVirtualAddress) is the
                    # only active address type. If not,
                    # TODO I need to update this code.
                    match_values.add(entry["value"])

        rule_match_addrs.append(list(match_values))

    return base_address, rule_names, rule_namespaces, rule_match_addrs, err_msg

