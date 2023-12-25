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

from analysis.analysis_models.network_analysis import DnsPacketAnalysis


def get_dns_analysis_values(sample, pcap_analysis):
    """
    Returns DNS analysis information in the following format:

    [
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

    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param pcap_analysis: PcapAnalysis object
    :type pcap_analysis: analysis.analysis_models.network_analysis.PcapAnalysis
    :return: DNS analysis information and error message, if any
    :rtype: list of dict, list
    """
    data = []
    error_msg = []

    try:
        objs = DnsPacketAnalysis.objects.filter(sample=sample,
                                                pcapanalysis=pcap_analysis)
    except (AttributeError, DnsPacketAnalysis.DoesNotExist) as err:
        error_msg = [str(err)]
        return data, error_msg

    for obj in objs:
        data.append({
            "ts": str(obj.ts),
            "query_domain": obj.query_domain,
            "query_type": obj.query_type,
            "query_class": obj.query_class,
            "response_type": obj.response_type,
            "response_class": obj.response_class,
            "response_ttl": obj.response_ttl,
            "response_data": obj.response_data,
        })

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
