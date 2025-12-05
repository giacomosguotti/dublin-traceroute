/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * \file   udpv4probe.cc
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   2017
 * \brief  Definition of the UDPv4Probe class
 *
 * This file contains the definition of the UDPv4Probe class, which represents
 * an UDP probe that will be sent over IPv4.
 *
 * \sa udpv4probe.h
 */

#include <memory>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <errno.h>
+#include <cstring>

#include "dublintraceroute/udpv4probe.h"
#include "dublintraceroute/common.h"
#include "dublintraceroute/exceptions.h"
#include "dublintraceroute/icmp_messages.h"


/** \brief method that sends the probe to the specified destination
 */
Tins::IP* UDPv4Probe::forge() {
	/* The payload is used to manipulate the UDP checksum, that will be
	 * used as hop identifier.
	 * The last two bytes will be adjusted to influence the hop identifier,
	 * which for UDP traceroutes is the UDP checksum.
	 */
	unsigned char payload[] = {'N', 'S', 'M', 'N', 'C', 0x00, 0x00};

	/* The identifier is used to identify and match a response packet to
	 * the corresponding sent packet
	 */
	uint16_t identifier = remote_port_ + ttl_;

	payload[5] = ((unsigned char *)&identifier)[0];
	payload[6] = ((unsigned char *)&identifier)[1];
	Tins::IP *packet = new Tins::IP(remote_addr_, local_addr_) /
		Tins::UDP(remote_port_, local_port_) /
		Tins::RawPDU((char *)payload);
	packet->ttl(ttl_);
	packet->flags(Tins::IP::DONT_FRAGMENT);

	// serialize the packet so we can extract source IP and checksum
	packet->serialize();

	packet->id(packet->rfind_pdu<Tins::UDP>().checksum());
	return packet;
}

Tins::IP &UDPv4Probe::send() {
    Tins::NetworkInterface iface;
    if (interface_.empty()) {
	    iface = Tins::NetworkInterface::default_interface();
    } else {
        iface = Tins::NetworkInterface(interface_);
    }

	if (packet == nullptr) {
		packet = forge();
	}

	// Use raw socket with SO_BINDTODEVICE to force interface
	// This ensures packets go out the specified interface regardless of routing table
		if (!interface_.empty()) {
			int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
			if (sock < 0) {
				throw std::runtime_error("Failed to create raw socket: " + std::string(strerror(errno)));
			}

			// Enable IP_HDRINCL so we can send our own IP header
			int one = 1;
			if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
				close(sock);
				throw std::runtime_error("Failed to set IP_HDRINCL: " + std::string(strerror(errno)));
			}

		// Bind socket to specific interface using SO_BINDTODEVICE
		if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface_.c_str(), interface_.length()) < 0) {
			close(sock);
			throw std::runtime_error("Failed to bind to device " + interface_ + ": " + std::string(strerror(errno)));
		}

		// Serialize the packet
		Tins::PDU::serialization_type serialized = packet->serialize();

		// Setup destination address
		struct sockaddr_in dest_addr;
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;
		dest_addr.sin_addr.s_addr = inet_addr(packet->dst_addr().to_string().c_str());
		// Send the packet
		ssize_t sent = sendto(sock, serialized.data(), serialized.size(), 0,
			(struct sockaddr*)&dest_addr, sizeof(dest_addr));
		close(sock);
	
		if (sent < 0) {
	        throw std::runtime_error("Failed to send packet: " + std::string(strerror(errno)));
	    }
    } else {
            // No specific interface - use default Tins sender
            Tins::PacketSender sender;
            sender.send(*packet, iface.name());
    }

	return *packet;
}

UDPv4Probe::~UDPv4Probe() {
	if (packet != nullptr)
		delete packet;
}
