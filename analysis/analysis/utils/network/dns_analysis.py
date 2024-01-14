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

from scapy.all import *
from scapy.layers.all import DNS, UDP
from scapy.layers.dns import dnstypes, dnsclasses

import os
import logging
import datetime

from analysis.analysis_models.network_analysis import DnsPacketAnalysis

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def _get_rdata_from_rtype(dns_record_content, type_):
    """
    This function constructs the relevant rdata value from the DNS response packet
    based on the response type.

    :param dns_record_content: Content in the returned DNS record
    :type dns_record_content: scapy.layers.dns.DNSRR<xxxxx>
    :return: Constructed response data
    :rtype: str
    """
    rdata = ""

    if type_ == "A" or type_ == "AAAA":
        rdata = dns_record_content.rdata

    elif type_ == "NS":
        rdata_ = dns_record_content.rdata
        if isinstance(rdata_, bytes):
            rdata = rdata_.decode("utf-8")
        else:
            rdata = str(rdata_)

    elif type_ == "TXT":
        rdata_ = dns_record_content.rdata
        if isinstance(rdata_, list):
            for entry in rdata_:
                if isinstance(entry, bytes):
                    rdata += entry.decode("utf-8")
                else:
                    rdata += str(entry)
        elif isinstance(rdata_, bytes):
            rdata = rdata_.decode("utf-8")
        else:
            rdata = str(rdata_)

    elif type_ == "SOA":
        # Concatenate all the fields in the SOA record into a single string
        rdata = f"mname={dns_record_content.mname.decode('utf-8').strip('.')}, " \
                f"rname={dns_record_content.rname.decode('utf-8').strip('.')}, " \
                f"serial={dns_record_content.serial}, " \
                f"refresh={dns_record_content.refresh}, " \
                f"retry={dns_record_content.retry}, " \
                f"expire={dns_record_content.expire}, " \
                f"minimum={dns_record_content.minimum}"

    return rdata


def analyze_dns_response_packet(dns_layer, arrival_time, info):
    """
    This function parses the given DNS response packet and extracts answer
    and nameserver records.

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

    # Traversing answer records
    for i in range(0, dns_layer.ancount):
        # For some reason, scapy adds a "." at the end of the qname. Strip it.
        qname = dns_layer.an[i].rrname.decode("utf-8").strip(".")
        type_ = dnstypes.get(dns_layer.an[i].type, dns_layer.an[i].type)
        rclass = dnsclasses.get(dns_layer.an[i].rclass, dns_layer.an[i].rclass)
        ttl = getattr(dns_layer.an[i], "ttl", None)
        rdata = _get_rdata_from_rtype(dns_layer.an[i], type_)

        info[qname]["response"].append({
            "ts": datetime.datetime.fromtimestamp(arrival_time),
            "type": type_,
            "class": rclass,
            "ttl": ttl,
            "rdata": rdata
        })

    # Traversing name server records
    for i in range(0, dns_layer.nscount):
        # For some reason, scapy adds a "." at the end of the qname. Strip it.
        qname_ = dns_layer.ns[i].rrname.decode("utf-8").strip(".")
        qname = dns_layer.qd[i].qname.decode("utf-8").strip(".") if qname_ == "" else qname_
        type_ = dnstypes.get(dns_layer.ns[i].type, dns_layer.ns[i].type)
        rclass = dnsclasses.get(dns_layer.ns[i].rclass, dns_layer.ns[i].rclass)
        ttl = getattr(dns_layer.ns[i], "ttl", None)
        rdata = _get_rdata_from_rtype(dns_layer.ns[i], type_)

        info[qname]["response"].append({
            "ts": datetime.datetime.fromtimestamp(arrival_time),
            "type": type_,
            "class": rclass,
            "ttl": ttl,
            "rdata": rdata
        })

    return info


def analyze_dns_query_packet(dns_layer, arrival_time):
    """
    This function parses specific information (query name, type of record,
    query class) from the given DNS query packet.

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


def build_qr_pairs(dns_packets):
    """
    This function builds query-response pairs from the given DNS packets list.
    Since all packets belong to the same TID, I'm going to match the source
    port of the querying machine with the destination port of the responding
    DNS server to build the query-response pairs.

    :param dns_packets: List of DNS packets with the same TID
    :type dns_packets: list of <class 'scapy.layers.l2.Ether'>
    :return: List of query-response pairs
    :rtype: list of tuples
    """
    qr_pairs = []
    tracker = {}

    for dns_packet in dns_packets:
        if dns_packet[DNS].qr == 0:
            # DNS query
            src_port = dns_packet[UDP].sport
            if src_port not in tracker:
                tracker[src_port] = []
            tracker[src_port].append(dns_packet)
        else:
            # DNS response
            dst_port = dns_packet[UDP].dport
            tracker[dst_port].append(dns_packet)

    for port in tracker:
        # (query, response) pair
        try:
            qr_pairs.append((tracker[port][0], tracker[port][1]))
        except IndexError:
            LOG.warning(f"Couldn't build query-response pair for: {tracker[port]}")
            qr_pairs.append((tracker[port][0], None))
            continue

    return qr_pairs


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
    info = []

    for tid in all_dns_packets:
        dns_packets = all_dns_packets[tid]

        # Group into query-response packets tuple
        dns_packets_paired = build_qr_pairs(dns_packets)

        # Extract information from each query-response pair
        for query_packet, response_packet in dns_packets_paired:
            info_ = analyze_dns_query_packet(query_packet[DNS],
                                             float(query_packet.time))
            if response_packet:
                info_ = analyze_dns_response_packet(response_packet[DNS],
                                                    float(response_packet.time),
                                                    info_)

            info.append(info_)

    if info:
        for entry in info:
            for qname in entry:
                if len(entry[qname]["response"]) > 0:
                    for response in entry[qname]["response"]:
                        DnsPacketAnalysis.objects.create(
                            sample=sample,
                            pcapanalysis=pcap_analysis,
                            query_domain=qname,
                            ts=entry[qname]["ts"],
                            query_type=entry[qname]["qtype"],
                            query_class=entry[qname]["qclass"],
                            response_type=response["type"],
                            response_class=response["class"],
                            response_ttl=response["ttl"],
                            response_data=response["rdata"],
                        )
                else:
                    # No response for query
                    DnsPacketAnalysis.objects.create(
                        sample=sample,
                        pcapanalysis=pcap_analysis,
                        query_domain=qname,
                        ts=entry[qname]["ts"],
                        query_type=entry[qname]["qtype"],
                        query_class=entry[qname]["qclass"],
                    )
