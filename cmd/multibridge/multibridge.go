package main

import (
	// "fmt"
	"net"
	"sync"
	// "time"

	log "github.com/Sirupsen/logrus"

	"github.com/contiv/libovsdb"
	"github.com/contiv/ofnet"
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

func main() {
	var err error
	ofPortIpAddressUpdateMonitorChan := make(chan map[string][]net.IP, 1024)

	datapathManager := ofnet.NewDatapathManager(&datapathConfig, ofPortIpAddressUpdateMonitorChan)

	// var vdsCount uint16 = 0
	// for vdsID, ovsbrname := range datapathConfig.ManagedVDSMap {
	// 	err = datapathManager.OvsdbDriverMap[vdsID]["local"].CreateOvsPort(fmt.Sprintf("%s_localToPolicy", vdsID), "", []ovsdbDriver.Iface{bridgeChainConfigMap[vdsID]["localToPolicy"]}, 0)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create %s-localToPolicy", vdsID)
	// 	}

	// 	err = datapathManager.OvsdbDriverMap[vdsID]["policy"].CreateOvsPort(fmt.Sprintf("%s_policyToLocal", vdsID), "", []ovsdbDriver.Iface{bridgeChainConfigMap[vdsID]["policyToLocal"]}, 0)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create %s-policyToLocal", vdsID)
	// 	}
	// 	err = datapathManager.OvsdbDriverMap[vdsID]["policy"].CreateOvsPort(fmt.Sprintf("%s_policyToCls", vdsID), "", []ovsdbDriver.Iface{bridgeChainConfigMap[vdsID]["policyToCls"]}, 0)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create %s-policyToCls", vdsID)
	// 	}

	// 	err = datapathManager.OvsdbDriverMap[vdsID]["cls"].CreateOvsPort(fmt.Sprintf("%s_clsToPolicy", vdsID), "", []ovsdbDriver.Iface{bridgeChainConfigMap[vdsID]["clsToPolicy"]}, 0)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create %s-clsToPolicy", vdsID)
	// 	}
	// 	err = datapathManager.OvsdbDriverMap[vdsID]["cls"].CreateOvsPort(fmt.Sprintf("%s_clsToUplink", vdsID), "", []ovsdbDriver.Iface{bridgeChainConfigMap[vdsID]["clsToUplink"]}, 0)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create %s-clsToUplink", vdsID)
	// 	}

	// 	err = datapathManager.OvsdbDriverMap[vdsID]["uplink"].CreateOvsPort(fmt.Sprintf("%s_uplinkToCls", vdsID), "", []ovsdbDriver.Iface{bridgeChainConfigMap[vdsID]["uplinkToCls"]}, 0)
	// 	if err != nil {
	// 		log.Fatalf("Failed to create %s-uplinkToCls", vdsID)
	// 	}

	// 	err = datapathManager.OvsdbDriverMap[vdsID]["local"].AddController("127.0.0.1", ofnet.OVS_CTRL_PORT_START+vdsCount*ofnet.OVS_CTRL_PORT_PER_VDS_OFFSET+1)
	// 	if err != nil {
	// 		log.Fatalf("Failed to connect bridge %s to controller", ovsbrname)
	// 	}
	// 	err = datapathManager.OvsdbDriverMap[vdsID]["policy"].AddController("127.0.0.1", ofnet.OVS_CTRL_PORT_START+vdsCount*ofnet.OVS_CTRL_PORT_PER_VDS_OFFSET+2)
	// 	if err != nil {
	// 		log.Fatalf("Failed to connect bridge %s-policy to controller", ovsbrname)
	// 	}
	// 	err = datapathManager.OvsdbDriverMap[vdsID]["cls"].AddController("127.0.0.1", ofnet.OVS_CTRL_PORT_START+vdsCount*ofnet.OVS_CTRL_PORT_PER_VDS_OFFSET+3)
	// 	if err != nil {
	// 		log.Fatalf("Failed to connect bridge %s-cls to controller", ovsbrname)
	// 	}
	// 	err = datapathManager.OvsdbDriverMap[vdsID]["uplink"].AddController("127.0.0.1", ofnet.OVS_CTRL_PORT_START+vdsCount*ofnet.OVS_CTRL_PORT_PER_VDS_OFFSET+4)
	// 	if err != nil {
	// 		log.Fatalf("Failed to connect bridge %s-uplink to controller", ovsbrname)
	// 	}

	// 	vdsCount++
	// }

	// make sure that all of datapath ofswitch is connected before initialize datapath
	datapathManager.InitializeDatapath()

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

	datapathManager.AddEveroutePolicyRule(rule1, ofnet.POLICY_DIRECTION_IN, ofnet.POLICY_TIER2)
	datapathManager.AddEveroutePolicyRule(rule2, ofnet.POLICY_DIRECTION_OUT, ofnet.POLICY_TIER2)

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
