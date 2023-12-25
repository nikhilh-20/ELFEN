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

from scapy.all import *
from scapy.layers.dns import dnstypes, dnsclasses

import os
import logging
import datetime

from analysis.analysis_models.network_analysis import DnsPacketAnalysis

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def analyze_dns_response_packet(dns_layer, arrival_time, info):
    """
    This function performs analysis on the given DNS response packet.

    :param dns_layer: The DNS layer to analyze in the packet.
    :type dns_layer: scapy.layers.dns.DNS
    :param arrival_time: Arrival time of packet
    :type arrival_time: float
    :param info: Structure containing associated DNS query information
    :type info: dict
    :return: Extracted DNS response-related information
    :rtype: dict
    """
    LOG.debug(f"Analyzing DNS response packet: {dns_layer}")

    for i in range(0, dns_layer.ancount):
        # For some reason, scapy adds a "." at the end of the qname. Strip it.
        qname = dns_layer.an[i].rrname.decode("utf-8").strip(".")
        type_ = dns_layer.an[i].type
        rclass = dns_layer.an[i].rclass
        ttl = dns_layer.an[i].ttl
        rdata = dns_layer.an[i].rdata

        info[qname]["response"].append({
            "ts": datetime.datetime.fromtimestamp(arrival_time),
            "type": dnstypes.get(type_, type_),
            "class": dnsclasses.get(rclass, rclass),
            "ttl": ttl,
            "rdata": rdata
        })

    return info


def analyze_dns_query_packet(dns_layer, arrival_time):
    """
    This function performs analysis on the given DNS query packet.

    :param dns_layer: The DNS layer to analyze in the packet.
    :type dns_layer: scapy.layers.dns.DNS
    :param arrival_time: Arrival time of packet
    :type arrival_time: float
    :return: Extracted DNS query-related information
    :rtype: dict
    """
    LOG.debug(f"Analyzing DNS query packet: {dns_layer}")
    info = {}

    for i in range(0, dns_layer.qdcount):
        # For some reason, scapy adds a "." at the end of the qname. Strip it.
        qname = dns_layer.qd[i].qname.decode("utf-8").strip(".")
        qtype = dns_layer.qd[i].qtype
        qclass = dns_layer.qd[i].qclass

        # It is not expected that there be multiple queries in a single DNS
        # query packet with the same query name.
        info[qname] = {
            "ts": datetime.datetime.fromtimestamp(arrival_time),
            "qtype": dnstypes.get(qtype, qtype),
            "qclass": dnsclasses.get(qclass, qclass),
            "response": []
        }

    return info


def dns_analysis(all_dns_packets, sample, pcap_analysis):
    """
    This functions performs analysis on the given DNS packet.

    :param all_dns_packets: Structure containing all DNS packets grouped by
                            Transaction ID (TID). Each TID contains a list of
                            associated DNS query and response packets
    :type all_dns_packets: dict
    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param pcap_analysis: PcapAnalysis object
    :type pcap_analysis: analysis.analysis_models.network_analysis.PcapAnalysis
    """
    LOG.debug(f"Starting analysis on DNS packets")
    info = {}

    # The below code assumes that there aren't multiple DNS queries for a single
    # domain name which have different responses (for ex: different A records).
    # In such a case, the last response will end up being recorded. It is assumed
    # that the first DNS response will be cached by Linux and subsequent queries
    # will be answered from the cache rather than querying the DNS server again.
    for tid in all_dns_packets:
        dns_packets = all_dns_packets[tid]
        if len(dns_packets) != 2:
            LOG.error(f"Expected 2 DNS packets for TID {tid}, got "
                      f"{len(dns_packets)}")
            continue

        info_ = {}
        for dns_packet in dns_packets:
            if not dns_packet[DNS].qr:
                # DNS query
                info_ = analyze_dns_query_packet(dns_packet[DNS],
                                                 float(dns_packet.time))
            else:
                # DNS response
                # This code path is expected to reach only after above if-block
                # code, so "info_" should contain required "response" key.
                # Otherwise, it's a bug.
                info_ = analyze_dns_response_packet(dns_packet[DNS],
                                                    float(dns_packet.time),
                                                    info_)

        info.update(info_)

    if info:
        for qname in info:
            for response in info[qname]["response"]:
                DnsPacketAnalysis.objects.create(
                    sample=sample,
                    pcapanalysis=pcap_analysis,
                    query_domain=qname,
                    ts=info[qname]["ts"],
                    query_type=info[qname]["qtype"],
                    query_class=info[qname]["qclass"],
                    response_type=response["type"],
                    response_class=response["class"],
                    response_ttl=response["ttl"],
                    response_data=response["rdata"],
                )
