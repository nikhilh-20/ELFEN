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

from analysis.analysis_models.utils import TaskStatus
from analysis.analysis_models.network_analysis import *

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
    else:
        LOG.warning(f"Unknown DNS record type: {type_}")

    return rdata


def analyze_dns_response_packet(dns_layer, arrival_time, sample, pcap_analysis):
    """
    This function parses the given DNS response packet and extracts answer
    and nameserver records.

    :param dns_layer: The DNS layer to analyze in the packet.
    :type dns_layer: scapy.layers.dns.DNS
    :param arrival_time: Arrival time of packet
    :type arrival_time: float
    :param sample: Sample object
    :type sample: web.models.SampleMetadataq
    :param pcap_analysis: PcapAnalysis object
    :type pcap_analysis: analysis.analysis_models.network_analysis.PcapAnalysis
    :return: Extracted DNS response-related information
    :rtype: dict
    """
    LOG.debug(f"Analyzing DNS response packet: {dns_layer}")

    # Traversing answer records
    for i in range(0, dns_layer.ancount):
        flags = (dns_layer.qr << 15) | (dns_layer.opcode << 11) | \
                (dns_layer.aa << 10) | (dns_layer.tc << 9) | (dns_layer.rd << 8) | \
                (dns_layer.ra << 7) | (dns_layer.z << 4) | dns_layer.rcode

        response_obj = DnsResponse.objects.create(ts=datetime.datetime.fromtimestamp(arrival_time),
                                                  sample=sample, pcapanalysis=pcap_analysis,
                                                  txid=dns_layer.id, flags=flags, rcode=dns_layer.rcode,
                                                  qdcount=dns_layer.qdcount, ancount=dns_layer.ancount,
                                                  nscount=dns_layer.nscount, arcount=dns_layer.arcount,
                                                  rrsection=RRSectionChoices.AN, status=TaskStatus.IN_PROGRESS)

        try:
            rtype = dnstypes.get(dns_layer.an[i].type, dns_layer.an[i].type)
            rclass = dnsclasses.get(dns_layer.an[i].rclass, dns_layer.an[i].rclass)
            ttl = getattr(dns_layer.an[i], "ttl", None)
            rdata = _get_rdata_from_rtype(dns_layer.an[i], rtype)
        except AttributeError as err:
            response_obj.errors = True
            response_obj.error_msg = f"AttributeError: {err}"
            response_obj.status = TaskStatus.ERROR
            response_obj.save()
            continue

        response_obj.response_type = rtype
        response_obj.response_class = rclass
        response_obj.response_ttl = ttl
        response_obj.response_data = rdata
        response_obj.status = TaskStatus.COMPLETE
        response_obj.save()

    # Traversing name server records
    for i in range(0, dns_layer.nscount):
        flags = (dns_layer.qr << 15) | (dns_layer.opcode << 11) | \
                (dns_layer.aa << 10) | (dns_layer.tc << 9) | (dns_layer.rd << 8) | \
                (dns_layer.ra << 7) | (dns_layer.z << 4) | dns_layer.rcode

        response_obj = DnsResponse.objects.create(ts=datetime.datetime.fromtimestamp(arrival_time),
                                                  sample=sample, pcapanalysis=pcap_analysis,
                                                  txid=dns_layer.id, flags=flags, rcode=dns_layer.rcode,
                                                  qdcount=dns_layer.qdcount, ancount=dns_layer.ancount,
                                                  nscount=dns_layer.nscount, arcount=dns_layer.arcount,
                                                  rrsection=RRSectionChoices.NS, status=TaskStatus.IN_PROGRESS)

        try:
            rtype = dnstypes.get(dns_layer.ns[i].type, dns_layer.ns[i].type)
            rclass = dnsclasses.get(dns_layer.ns[i].rclass, dns_layer.ns[i].rclass)
            ttl = getattr(dns_layer.ns[i], "ttl", None)
            rdata = _get_rdata_from_rtype(dns_layer.ns[i], rtype)
        except AttributeError as err:
            response_obj.errors = True
            response_obj.error_msg = f"AttributeError: {err}"
            response_obj.status = TaskStatus.ERROR
            response_obj.save()
            continue

        response_obj.response_type = rtype
        response_obj.response_class = rclass
        response_obj.response_ttl = ttl
        response_obj.response_data = rdata
        response_obj.status = TaskStatus.COMPLETE
        response_obj.save()

    # Traversing additional resource records
    for i in range(0, dns_layer.arcount):
        opt_data = []
        flags = (dns_layer.qr << 15) | (dns_layer.opcode << 11) | \
                (dns_layer.aa << 10) | (dns_layer.tc << 9) | (dns_layer.rd << 8) | \
                (dns_layer.ra << 7) | (dns_layer.z << 4) | dns_layer.rcode

        response_obj = DnsResponse.objects.create(ts=datetime.datetime.fromtimestamp(arrival_time),
                                                  sample=sample, pcapanalysis=pcap_analysis,
                                                  txid=dns_layer.id, flags=flags, rcode=dns_layer.rcode,
                                                  qdcount=dns_layer.qdcount, ancount=dns_layer.ancount,
                                                  nscount=dns_layer.nscount, arcount=dns_layer.arcount,
                                                  rrsection=RRSectionChoices.AR, status=TaskStatus.IN_PROGRESS)

        # This additional if-block is required because some malware set arcount
        # to 1 but don't include any additional records. Just using a for loop
        # on the ith index will throw an IndexError exception.
        if i < len(dns_layer.ar):
            if isinstance(dns_layer.ar[i].rdata, str):
                opt_data.append({
                    "type": dns_layer.ar[i].type,
                    "data": dns_layer.ar[i].rdata
                })
            elif isinstance(dns_layer.ar[i].rdata, list):
                for j in dns_layer.ar[i].rdata:
                    opt_data.append({
                        "type": dns_layer.ar[i].type,
                        "optcode": dns_layer.ar[i].rdata[j].optcode,
                        "data": dns_layer.ar[i].rdata[j].payload.original.decode("utf-8")
                    })
            else:
                LOG.error(f"Unknown DNS AR type: {dns_layer.ar[i].rdata}")

        response_obj.opt_data = opt_data
        response_obj.status = TaskStatus.COMPLETE
        response_obj.save(update_fields=["opt_data", "status"])

    # Look for response errors
    if dns_layer.rcode != 0:
        flags = (dns_layer.qr << 15) | (dns_layer.opcode << 11) | \
                (dns_layer.aa << 10) | (dns_layer.tc << 9) | (dns_layer.rd << 8) | \
                (dns_layer.ra << 7) | (dns_layer.z << 4) | dns_layer.rcode

        DnsResponse.objects.create(ts=datetime.datetime.fromtimestamp(arrival_time),
                                   sample=sample, pcapanalysis=pcap_analysis,
                                   txid=dns_layer.id, flags=flags, rcode=dns_layer.rcode,
                                   qdcount=dns_layer.qdcount, ancount=dns_layer.ancount,
                                   nscount=dns_layer.nscount, arcount=dns_layer.arcount,
                                   rrsection=None, status=TaskStatus.COMPLETE)

    return True


def analyze_dns_query_packet(dns_layer, arrival_time, sample, pcap_analysis):
    """
    This function parses specific information (query name, type of record,
    query class) from the given DNS query packet.

    :param dns_layer: The DNS layer to analyze in the packet.
    :type dns_layer: scapy.layers.dns.DNS
    :param arrival_time: Arrival time of packet
    :type arrival_time: float
    :param sample: Sample object
    :type sample: web.models.SampleMetadata
    :param pcap_analysis: PcapAnalysis object
    :type pcap_analysis: analysis.analysis_models.network_analysis.PcapAnalysis
    :return: Status of DNS query packet processing
    :rtype: bool
    """
    LOG.debug(f"Analyzing DNS query packet: {dns_layer}")

    for i in range(0, dns_layer.qdcount):
        flags = (dns_layer.qr << 15) | (dns_layer.opcode << 11) | \
                (dns_layer.aa << 10) | (dns_layer.tc << 9) | (dns_layer.rd << 8) | \
                (dns_layer.ra << 7) | (dns_layer.z << 4) | dns_layer.rcode

        query_obj = DnsQuery.objects.create(ts=datetime.datetime.fromtimestamp(arrival_time),
                                            sample=sample, pcapanalysis=pcap_analysis,
                                            txid=dns_layer.id, flags=flags,
                                            qdcount=dns_layer.qdcount, ancount=dns_layer.ancount,
                                            nscount=dns_layer.nscount, arcount=dns_layer.arcount,
                                            rrsection=RRSectionChoices.QD, status=TaskStatus.IN_PROGRESS)

        try:
            qname = dns_layer.qd[i].qname.decode("utf-8").strip(".")
            qtype = dns_layer.qd[i].qtype
            qclass = dns_layer.qd[i].qclass
        except AttributeError as err:
            # There are some weird cases where a DNS packet isn't parsed
            # correctly. The domain name is in the packet data #TODO.
            query_obj.errors = True
            query_obj.error_msg = str(err)
            query_obj.status = TaskStatus.ERROR
            query_obj.save()
            continue

        query_obj.query_domain = qname
        query_obj.query_type = dnstypes.get(qtype, qtype)
        query_obj.query_class = dnsclasses.get(qclass, qclass)
        query_obj.status = TaskStatus.COMPLETE
        query_obj.save()

    for i in range(0, dns_layer.arcount):
        opt_data = []
        flags = (dns_layer.qr << 15) | (dns_layer.opcode << 11) | \
                (dns_layer.aa << 10) | (dns_layer.tc << 9) | (dns_layer.rd << 8) | \
                (dns_layer.ra << 7) | (dns_layer.z << 4) | dns_layer.rcode

        query_obj = DnsQuery.objects.create(ts=datetime.datetime.fromtimestamp(arrival_time),
                                            sample=sample, pcapanalysis=pcap_analysis,
                                            txid=dns_layer.id, flags=flags,
                                            qdcount=dns_layer.qdcount, ancount=dns_layer.ancount,
                                            nscount=dns_layer.nscount, arcount=dns_layer.arcount,
                                            rrsection=RRSectionChoices.AR, status=TaskStatus.IN_PROGRESS)

        # This additional if-block is required because some malware set arcount
        # to 1 but don't include any additional records. Just using a for loop
        # on the ith index will throw an IndexError exception.
        if i < len(dns_layer.ar):
            if isinstance(dns_layer.ar[i].rdata, str):
                opt_data.append({
                    "type": dns_layer.ar[i].type,
                    "data": dns_layer.ar[i].rdata
                })
            elif isinstance(dns_layer.ar[i].rdata, list):
                for j in dns_layer.ar[i].rdata:
                    opt_data.append({
                        "type": dns_layer.ar[i].type,
                        "optcode": dns_layer.ar[i].rdata[j].optcode,
                        "data": dns_layer.ar[i].rdata[j].payload.original.decode("utf-8")
                    })
            else:
                LOG.error(f"Unknown DNS AR type: {dns_layer.ar[i].rdata}")

        query_obj.opt_data = opt_data
        query_obj.status = TaskStatus.COMPLETE
        query_obj.save(update_fields=["opt_data", "status"])

    return True


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

    for tid in all_dns_packets:
        dns_packets = all_dns_packets[tid]

        # Group into query-response packets tuple
        dns_packets_paired = build_qr_pairs(dns_packets)

        # Extract information from each query-response pair
        for query_packet, response_packet in dns_packets_paired:
            analyze_dns_query_packet(query_packet[DNS],
                                     float(query_packet.time),
                                     sample, pcap_analysis)
            if response_packet:
                analyze_dns_response_packet(response_packet[DNS],
                                            float(response_packet.time),
                                            sample, pcap_analysis)
