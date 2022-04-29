/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofctrl

import (
	"encoding/binary"
	"math/rand"
	"net"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/util"

	log "github.com/Sirupsen/logrus"
)

type Packet struct {
	SrcMac     net.HardwareAddr
	DstMac     net.HardwareAddr
	SrcIP      net.IP
	DstIP      net.IP
	IPProtocol uint8
	IPLength   uint16
	IPFlags    uint16
	TTL        uint8
	SrcPort    uint16
	DstPort    uint16
	TCPFlags   uint8
	ICMPType   uint8
	ICMPCode   uint8

	ICMPEchoID  uint16
	ICMPEchoSeq uint16
}

type PacketHeader struct {
	IPHeader   *protocol.IPv4
	TCPHeader  *protocol.TCP
	UDPHeader  *protocol.UDP
	ICMPHeader *protocol.ICMP
	ARPHeader  *protocol.ARP
}

type PacketOut struct {
	InPort  uint32
	OutPort *uint32
	SrcMac  net.HardwareAddr
	DstMac  net.HardwareAddr
	Header  *PacketHeader

	Actions []openflow13.Action
}

func ConstructPacketOut(packet *Packet) *PacketOut {
	// generate packet Header from Packet defnition
	packetOut := new(PacketOut)
	packetOut.SrcMac = packet.SrcMac
	packetOut.DstMac = packet.DstMac
	packetOut.Header = new(PacketHeader)
	packetOut.Header.IPHeader = new(protocol.IPv4)
	packetOut.Header.IPHeader.Version = 4
	packetOut.Header.IPHeader.Flags = packet.IPFlags
	packetOut.Header.IPHeader.NWSrc = packet.SrcIP
	packetOut.Header.IPHeader.NWDst = packet.DstIP

	switch packet.IPProtocol {
	case protocol.Type_ICMP:
		packetOut.Header.ICMPHeader = new(protocol.ICMP)
		packetOut.Header.ICMPHeader.Type = packet.ICMPType
		packetOut.Header.ICMPHeader.Code = packet.ICMPCode
	case protocol.Type_TCP:
		packetOut.Header.TCPHeader = new(protocol.TCP)
		packetOut.Header.TCPHeader.Code = packet.TCPFlags
		packetOut.Header.TCPHeader.PortSrc = packet.SrcPort
		packetOut.Header.TCPHeader.PortDst = packet.DstPort
	case protocol.Type_UDP:
		packetOut.Header.UDPHeader = new(protocol.UDP)
		packetOut.Header.UDPHeader.PortSrc = packet.SrcPort
		packetOut.Header.UDPHeader.PortDst = packet.DstPort
	default:
		log.Infof("unsupport protocol")
	}

	return packetOut
}

func SendPacket(sw *OFSwitch, packetOut *PacketOut) error {
	// generate openflow packetOut from ofctrl packet out
	ofPacketOut := openflow13.NewPacketOut()
	ofPacketOut.InPort = packetOut.InPort

	ofPacketOut.Data = GeneratePacketOutData(packetOut)
	for _, action := range packetOut.Actions {
		ofPacketOut.AddAction(action)
	}
	if packetOut.OutPort != nil {
		log.Infof("send packet to port %v", *packetOut.OutPort)
		ofPacketOut.AddAction(openflow13.NewActionOutput(*packetOut.OutPort))
	} else {
		// default send packet to first table. openflow13 spec defined
		ofPacketOut.AddAction(openflow13.NewActionOutput(openflow13.P_TABLE))
	}
	for _, action := range ofPacketOut.Actions {
		log.Infof("##### send packetout action %v", action)
	}

	sw.Send(ofPacketOut)

	return nil
}

func GeneratePacketOutData(p *PacketOut) *protocol.Ethernet {
	var data util.Message
	ethPacket := &protocol.Ethernet{
		HWDst: p.DstMac,
		HWSrc: p.SrcMac,
	}

	switch {
	case p.Header.TCPHeader != nil:
		p.Header.IPHeader.Protocol = protocol.Type_TCP
		p.Header.IPHeader.DSCP = 16
		p.Header.IPHeader.Data = p.Header.TCPHeader
	case p.Header.UDPHeader != nil:
		p.Header.IPHeader.Protocol = protocol.Type_UDP
		p.Header.IPHeader.Data = p.Header.UDPHeader
	case p.Header.ICMPHeader != nil:
		p.Header.IPHeader.Protocol = protocol.Type_ICMP
		p.Header.IPHeader.Data = p.Header.ICMPHeader
	}

	data = p.Header.IPHeader
	ethPacket.Ethertype = protocol.IPv4_MSG
	ethPacket.Data = data

	// log.Infof("##### send eth packet through %v, tos %v", ethPacket, p.Header.IPHeader.DSCP)
	return ethPacket
}

func (p *PacketIn) GetMatches() *Matchers {
	matches := make([]*MatchField, 0, len(p.Match.Fields))
	for i := range p.Match.Fields {
		matches = append(matches, NewMatchField(&p.Match.Fields[i]))
	}
	return &Matchers{matches: matches}
}

func GenerateTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort, srcPort uint16, tcpFlags *uint8) *PacketOut {
	tcpHeader := GenerateTCPHeader(dstPort, srcPort, tcpFlags)
	var pktOut *PacketOut
	ipHeader := &protocol.IPv4{
		Version:        4,
		IHL:            5,
		Length:         20 + tcpHeader.Len(),
		Id:             uint16(rand.Int()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       protocol.Type_TCP,
		Checksum:       0,
		NWSrc:          srcIP,
		NWDst:          dstIP,
	}

	packetOutHeader := &PacketHeader{
		IPHeader:  ipHeader,
		TCPHeader: tcpHeader,
	}
	pktOut = &PacketOut{
		SrcMac: srcMAC,
		DstMac: dstMAC,
		Header: packetOutHeader,
	}

	return pktOut
}

func GenerateSimpleIPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) *PacketOut {
	icmpHeader := GenerateICMPHeader(nil, nil)
	ipHeader := &protocol.IPv4{
		Version:        4,
		IHL:            5,
		Length:         20 + icmpHeader.Len(),
		Id:             uint16(rand.Int()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       protocol.Type_ICMP,
		Checksum:       0,
		NWSrc:          srcIP,
		NWDst:          dstIP,
	}

	packetOutHeader := &PacketHeader{
		IPHeader:   ipHeader,
		ICMPHeader: icmpHeader,
	}
	pktOut := &PacketOut{
		SrcMac: srcMAC,
		DstMac: dstMAC,
		Header: packetOutHeader,
	}
	return pktOut
}

func GenerateTCPHeader(dstPort, srcPort uint16, flags *uint8) *protocol.TCP {
	header := protocol.NewTCP()
	if dstPort != 0 {
		header.PortDst = dstPort
	} else {
		header.PortDst = uint16(rand.Uint32())
	}
	if srcPort != 0 {
		header.PortSrc = srcPort
	} else {
		header.PortSrc = uint16(rand.Uint32())
	}
	header.AckNum = rand.Uint32()
	header.AckNum = header.AckNum + 1
	header.HdrLen = 20
	if flags != nil {
		header.Code = *flags
	} else {
		header.Code = uint8(1 << 1)
	}
	return header
}

func GenerateICMPHeader(icmpType, icmpCode *uint8) *protocol.ICMP {
	header := protocol.NewICMP()
	if icmpType != nil {
		header.Type = *icmpType
	} else {
		header.Type = 8
	}
	if icmpCode != nil {
		header.Code = *icmpCode
	} else {
		header.Code = 0
	}
	identifier := uint16(rand.Uint32())
	seq := uint16(1)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data, identifier)
	binary.BigEndian.PutUint16(data[2:], seq)
	return header
}
