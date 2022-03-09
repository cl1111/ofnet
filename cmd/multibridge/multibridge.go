package main

import (
	// "fmt"
	"net"
	// "sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libovsdb"
	"github.com/contiv/ofnet"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ovsdbDriver"
)

const (
	LOCALBRIDGE_SUFFIX  = "local"
	POLICYBRIDGE_SUFFIX = "policy"
	CLSBRIDGE_SUFFIX    = "cls"
	UPLINKBRIDGE_SUFFIX = "uplink"
)

var (
	bridgeChainConfigMap = map[string]map[string]ovsdbDriver.Iface{
		"vds1": {
			"localToPolicy": {
				IfaceName: "vds1_localToPolicy",
				IfaceType: "patch",
				OfPort:    uint32(101),
				Options: map[string]string{
					"peer": "vds1_policyToLocal",
				},
			},
			"policyToLocal": {
				IfaceName: "vds1_policyToLocal",
				IfaceType: "patch",
				OfPort:    uint32(102),
				Options: map[string]string{
					"peer": "vds1_localToPolicy",
				},
			},
			"policyToCls": {
				IfaceName: "vds1_policyToCls",
				IfaceType: "patch",
				OfPort:    uint32(201),
				Options: map[string]string{
					"peer": "vds1_clsToPolicy",
				},
			},
			"clsToPolicy": {
				IfaceName: "vds1_clsToPolicy",
				IfaceType: "patch",
				OfPort:    uint32(202),
				Options: map[string]string{
					"peer": "vds1_policyToCls",
				},
			},
			"clsToUplink": {
				IfaceName: "vds1_clsToUplink",
				IfaceType: "patch",
				OfPort:    uint32(301),
				Options: map[string]string{
					"peer": "vds1_uplinkToCls",
				},
			},
			"uplinkToCls": {
				IfaceName: "vds1_uplinkToCls",
				IfaceType: "patch",
				OfPort:    uint32(302),
				Options: map[string]string{
					"peer": "vds1_clsToUplink",
				},
			},
		},
		"vds2": {
			"localToPolicy": {
				IfaceName: "vds2_localToPolicy",
				IfaceType: "patch",
				OfPort:    uint32(101),
				Options: map[string]string{
					"peer": "vds2_policyToLocal",
				},
			},
			"policyToLocal": {
				IfaceName: "vds2_policyToLocal",
				IfaceType: "patch",
				OfPort:    uint32(102),
				Options: map[string]string{
					"peer": "vds2_localToPolicy",
				},
			},
			"policyToCls": {
				IfaceName: "vds2_policyToCls",
				IfaceType: "patch",
				OfPort:    uint32(201),
				Options: map[string]string{
					"peer": "vds2_clsToPolicy",
				},
			},
			"clsToPolicy": {
				IfaceName: "vds2_clsToPolicy",
				IfaceType: "patch",
				OfPort:    uint32(202),
				Options: map[string]string{
					"peer": "vds2_policyToCls",
				},
			},
			"clsToUplink": {
				IfaceName: "vds2_clsToUplink",
				IfaceType: "patch",
				OfPort:    uint32(301),
				Options: map[string]string{
					"peer": "vds2_uplinkToCls",
				},
			},
			"uplinkToCls": {
				IfaceName: "vds2_uplinkToCls",
				IfaceType: "patch",
				OfPort:    uint32(302),
				Options: map[string]string{
					"peer": "vds2_clsToUplink",
				},
			},
		},
	}
)

var (
	datapathConfig = ofnet.DatapathConfig{
		ManagedVDSMap: map[string]string{
			"ovsbr0": "ovsbr0",
		},
	}

	rule1 = &ofnet.EveroutePolicyRule{
		RuleId:     "rule1",
		IpProtocol: uint8(1),
		SrcIpAddr:  "10.100.100.1",
		DstIpAddr:  "10.100.100.2",
		Action:     "allow",
	}
	rule2 = &ofnet.EveroutePolicyRule{
		RuleId:     "rule2",
		IpProtocol: uint8(6),
		DstIpAddr:  "10.100.100.3",
		DstPort:    80,
		Action:     "deny",
	}
)

var (
	srcMac, _ = net.ParseMAC("00:aa:aa:aa:aa:aa")
	dstMac, _ = net.ParseMAC("00:aa:aa:aa:aa:ab")
	srcIP     = net.ParseIP("10.0.1.11")
	dstIP     = net.ParseIP("10.0.1.12")

	packet = &ofctrl.Packet{
		SrcMac:     srcMac,
		DstMac:     dstMac,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		IPProtocol: uint8(6),
		IPLength:   uint16(5),
		IPFlags:    uint16(0),
		TTL:        uint8(60),
		SrcPort:    uint16(8080),
		DstPort:    uint16(80),
		TCPFlags:   uint8(2),
	}
)

func main() {
	var err error
	ofPortIpAddressUpdateMonitorChan := make(chan map[string][]net.IP, 1024)
	stopChan := make(chan struct{})

	datapathManager := ofnet.NewDatapathManager(&datapathConfig, ofPortIpAddressUpdateMonitorChan)

	// make sure that all of datapath ofswitch is connected before initialize datapath
	datapathManager.InitializeDatapath(stopChan)

	ovsClient, err := libovsdb.ConnectUnix("/var/run/openvswitch/db.sock")
	if err != nil {
		log.Fatalf("error when init ovsdbEventHandler ovsClient: %v", err)
	}

	ovsdbEventHandler := ofnet.NewOvsdbEventHandler(ovsClient)
	ovsdbEventHandler.RegisterOvsdbEventCallbackHandlerFunc(ofnet.OvsdbEventHandlerFuncs{
		LocalEndpointAddFunc: func(endpoint ofnet.Endpoint) {
			err := datapathManager.AddLocalEndpoint(&endpoint)
			if err != nil {
			}
		},
		LocalEndpointDeleteFunc: func(endpoint ofnet.Endpoint) {
			err := datapathManager.RemoveLocalEndpoint(&endpoint)
			if err != nil {
			}
		},
	})

	err = ovsdbEventHandler.StartOvsdbEventHandler()
	if err != nil {
		log.Fatalf("Failed to start ovsdbEventHandler: %v", err)
	}

	log.Infof("###### add rule to datatpath")
	datapathManager.AddEveroutePolicyRule(rule1, ofnet.POLICY_DIRECTION_IN, ofnet.POLICY_TIER2)
	datapathManager.AddEveroutePolicyRule(rule2, ofnet.POLICY_DIRECTION_OUT, ofnet.POLICY_TIER2)

	ticker := time.NewTicker(1 * time.Second)
	var outport *uint32 = nil
	go func() {
		for {
			select {
			case <-stopChan:
				return
			case t := <-ticker.C:
				log.Infof("send active probe packet: %v at %v", packet, t)
				sendActiveProbePacket(datapathManager.OfSwitchMap["ovsbr0"][ofnet.LOCAL_BRIDGE_KEYWORD], 16, packet, 10, outport)
			}
		}
	}()

	<-stopChan

	// var wg sync.WaitGroup
	// wg.Add(1)
	// wg.Wait()
}

func sendActiveProbePacket(sw *ofctrl.OFSwitch, tag uint8, packet *ofctrl.Packet, inPort uint32, outPort *uint32) error {
	packetOut := ofctrl.ConstructPacketOut(packet)
	packetOut.InPort = inPort
	packetOut.OutPort = outPort

	field, err := openflow13.FindFieldHeaderByName("nxm_of_ip_tos", true)
	if err != nil {
		return err
	}
	loadOfAction := openflow13.NewNXActionRegLoad(openflow13.NewNXRange(2, 7).ToOfsBits(), field, uint64(tag))
	packetOut.Actions = append(packetOut.Actions, loadOfAction)

	return ofctrl.SendPacket(sw, packetOut)
}

func recvActiveProbePacket() error {

	return nil
}

type OfBridge struct {
}
