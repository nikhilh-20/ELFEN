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

from analysis.analysis_models.network_analysis import DnsQuery, DnsResponse, RRSection,\
                                                      rcode_mapping


def get_dns_analysis_values(sample, pcap_analysis):
    """
    Returns DNS analysis information in the following format:

    {
        "<dns_transaction_id>": {
            "query": {"ts": "<timestamp>", "flags": "<flags>", "qdcount": <qdcount>,
                      "ancount": <ancount>, "nscount": <nscount>, "arcount": <arcount>,
                      "qd": [{"query_domain": "<query_domain>", "query_type": "<query_type>",
                              "query_class": "<query_class>"}, ...],
                      "ar": [{"query": ["<query>", ...]}]}
            "response": {"ts": "<timestamp>", "flags": "<flags>", "rcode": "<rcode>",
                         "qdcount": <qdcount>, "ancount": <ancount>, "nscount": <nscount>,
                         "arcount": <arcount>,
                         "an": [{"response_type": "<response_type>", "response_class": "<response_class>",
                                 "response_ttl": "<response_ttl>", "response_data": "<response_data'},
                                ...],
                         "ns": [{"response_type": "<response_type>", "response_class": "<response_class>",
                                 "response_ttl": "<response_ttl>", "response_data": "<response_data'},
                                 ...],
                         "ar": [{"response": ["<response>", ...]}]}
        },
        ...
    }

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param pcap_analysis: PcapAnalysis object
    :type pcap_analysis: analysis.analysis_models.network_analysis.PcapAnalysis
    :return: DNS analysis information and error message, if any
    :rtype: dict, list
    """
    data = {}
    error_msg = []

    try:
        query_objs = DnsQuery.objects.filter(sample=sample,
                                             pcapanalysis=pcap_analysis)
    except (AttributeError, DnsQuery.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    for q_obj in query_objs:
        if hex(q_obj.txid) not in data:
            data[hex(q_obj.txid)] = {"query": {}}
            data[hex(q_obj.txid)]["query"] = {
                "ts": str(q_obj.ts),
                "flags": hex(q_obj.flags),
                "qdcount": q_obj.qdcount,
                "ancount": q_obj.ancount,
                "nscount": q_obj.nscount,
                "arcount": q_obj.arcount,
                "qd": [],
                "ar": [],
            }

        if q_obj.query_domain:
            data[hex(q_obj.txid)]["query"]["qd"].append({
                "query_domain": q_obj.query_domain,
                "query_type": q_obj.query_type,
                "query_class": q_obj.query_class
            })

        if q_obj.opt_data:
            data[hex(q_obj.txid)]["query"]["ar"].append(q_obj.opt_data)

    for txid in data:
        try:
            response_objs = DnsResponse.objects.filter(sample=sample, txid=int(txid, 16),
                                                       pcapanalysis=pcap_analysis)
            for r_obj in response_objs:
                if "response" not in data[txid]:
                    data[txid]["response"] = {
                        "ts": str(r_obj.ts),
                        "flags": hex(r_obj.flags),
                        "rcode": rcode_mapping.get(r_obj.rcode, "Unknown"),
                        "qdcount": r_obj.qdcount,
                        "ancount": r_obj.ancount,
                        "nscount": r_obj.nscount,
                        "arcount": r_obj.arcount,
                        "an": [],
                        "ns": [],
                        "ar": [],
                    }

                if r_obj.response_data:
                    if r_obj.rrsection == RRSection.AN:
                        data[txid]["response"]["an"].append({
                            "response_type": r_obj.response_type,
                            "response_class": r_obj.response_class,
                            "response_ttl": r_obj.response_ttl,
                            "response_data": r_obj.response_data
                        })
                    elif r_obj.rrsection == RRSection.NS:
                        data[txid]["response"]["ns"].append({
                            "response_type": r_obj.response_type,
                            "response_class": r_obj.response_class,
                            "response_ttl": r_obj.response_ttl,
                            "response_data": r_obj.response_data
                        })

                if r_obj.rrsection == RRSection.AR:
                    if r_obj.opt_data:
                        data[txid]["response"]["ar"].append(r_obj.opt_data)

        except (AttributeError, DnsResponse.DoesNotExist) as err:
            continue

    return data, error_msg


def get_pcap_analysis_values(parent_task):
    """
    Returns pcap analysis information in the following format:

    {
        "dns": [
            {
                "ts": "10:25:53.565268",
                "query_domain": "google.com",
                "query_type": "A",
                "query_class": "IN",
                "response_type": "A",
                "response_class": "IN",
                "response_ttl": 30,
                "response_data": "142.250.195.206"
            }
        ]
    }

    :param parent_task: Parent task object
    :type parent_task: analysis.models.TaskMetadata
    :return: Pcap analysis information and error message, if any
    :rtype: dict, list
    """
    data = {
        "dns": []
    }
    error_msg = []

    sample = parent_task.sha256
    pcap_analysis = parent_task.taskreports.network_reports.pcapanalysis

    dns_info, error_msg_ = get_dns_analysis_values(sample, pcap_analysis)
    if error_msg_:
        error_msg.extend(error_msg_)
    data["dns"] = dns_info

    return data, error_msg
