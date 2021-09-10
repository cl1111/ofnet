package ofnet

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	cmap "github.com/streamrail/concurrent-map"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
)

const (
	HIGH_MATCH_FLOW_PRIORITY   = 300
	MID_MATCH_FLOW_PRIORITY    = 200
	NORMAL_MATCH_FLOW_PRIORITY = 100
	DEFAULT_FLOW_PRIORITY      = 10
	FLOW_MATCH_OFFSET          = 5
)

const (
	// bridge chain patch port const
	LOCAL_TO_POLICY_PORT = 101
	POLICY_TO_LOCAL_PORT = 102
	POLICY_TO_CLS_PORT   = 201
	CLS_TO_POLICY_PORT   = 202
	CLS_TO_UPLINK_PORT   = 301
	UPLINK_TO_CLS_PORT   = 302
)

const (
	IP_BROADCAST_ADDR = "255.255.255.255"
	LOOP_BACK_ADDR    = "127.0.0.1"
)

const (
	LOCAL_BRIDGE_KEYWORD  = "local"
	POLICY_BRIDGE_KEYWORD = "policy"
	CLS_BRIDGE_KEYWORD    = "cls"
	UPLINK_BRIDGE_KEYWORD = "uplink"
)

type Bridge interface {
	BridgeInit() error
	BridgeReset() error

	AddLocalEndpoint(endpoint *Endpoint) error
	RemoveLocalEndpoint(endpoint *Endpoint) error
	AddVNFInstance() error
	RemoveVNFInstance() error

	AddSFCRule() error
	RemoveSFCRule() error
	AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*ofctrl.Flow, error)
	RemoveMicroSegmentRule(rule *EveroutePolicyRule) error

	IsSwitchConnected() bool

	// of control app interface
	// A Switch connected to the controller
	SwitchConnected(sw *ofctrl.OFSwitch)

	// Switch disconnected from the controller
	SwitchDisconnected(sw *ofctrl.OFSwitch)

	// Controller received a packet from the switch
	PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn)

	// Controller received a multi-part reply from the switch
	MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply)
}

type DatapathManager struct {
	BridgeChainMap map[string]map[string]Bridge                 // map vds to bridge instance map
	OvsdbDriverMap map[string]map[string]*ovsdbDriver.OvsDriver // map vds to bridge ovsdbDriver map
	OfSwitchMap    map[string]map[string]*ofctrl.OFSwitch
	ControllerMap  map[string]map[string]*ofctrl.Controller

	localEndpointDB           cmap.ConcurrentMap       // list of local endpoint map
	ofPortIpAddressUpdateChan chan map[string][]net.IP // map bridgename-ofport to endpoint ips
	datapathConfig            *DatapathConfig
	ruleMux                   sync.RWMutex
	Rules                     map[string]*EveroutePolicyRuleEntry // rules database
}

type DatapathConfig struct {
	ManagedVDSMap map[string]string // map vds to ovsbr-name
}

type Endpoint struct {
	IPAddr     net.IP
	IPv6Addr   net.IP
	PortNo     uint32 // endpoint of port
	MacAddrStr string
	VlanID     uint16 // endpoint vlan id
	BridgeName string // bridge name that endpoint attached to
}

type EveroutePolicyRule struct {
	RuleId     string // Unique identifier for the rule
	Priority   int    // Priority for the rule (1..100. 100 is highest)
	SrcIpAddr  string // source IP addrss and mask
	DstIpAddr  string // Destination IP address and mask
	IpProtocol uint8  // IP protocol number
	SrcPort    uint16 // Source port
	DstPort    uint16 // destination port
	Action     string // rule action: 'accept' or 'deny'
}

type EveroutePolicyRuleEntry struct {
	EveroutePolicyRule *EveroutePolicyRule
	RuleFlowMap        map[string]*ofctrl.Flow
}

// type RoundInfo struct {
// 	previousRoundNum uint64
// 	curRoundNum      uint64
// }

// Datapath manager act as openflow controller:
// 1. event driven local endpoint info crud and related flow update,
// 2. collect local endpoint ip learned from different ovsbr(1 per vds), and sync it to management plane
func NewDatapathManager(datapathConfig *DatapathConfig, ofPortIpAddressUpdateChan chan map[string][]net.IP) *DatapathManager {
	datapathManager := new(DatapathManager)
	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.OvsdbDriverMap = make(map[string]map[string]*ovsdbDriver.OvsDriver)
	datapathManager.OfSwitchMap = make(map[string]map[string]*ofctrl.OFSwitch)
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.Rules = make(map[string]*EveroutePolicyRuleEntry)
	// NOTE deepcopy
	datapathManager.datapathConfig = datapathConfig
	datapathManager.localEndpointDB = cmap.New()

	var vdsCount int = 0
	// vdsID equals to ovsbrname
	for vdsID, ovsbrname := range datapathConfig.ManagedVDSMap {
		// initialize vds bridge chain
		localBridge := NewLocalBridge(ovsbrname, datapathManager)
		policyBridge := NewPolicyBridge(ovsbrname, datapathManager)
		clsBridge := NewClsBridge(ovsbrname, datapathManager)
		uplinkBridge := NewUplinkBridge(ovsbrname, datapathManager)
		vdsBridgeMap := make(map[string]Bridge)
		vdsBridgeMap["local"] = localBridge
		vdsBridgeMap["policy"] = policyBridge
		vdsBridgeMap["cls"] = clsBridge
		vdsBridgeMap["uplink"] = uplinkBridge
		datapathManager.BridgeChainMap[vdsID] = vdsBridgeMap

		// initialize of controller
		vdsOfControllerMap := make(map[string]*ofctrl.Controller)
		vdsOfControllerMap["local"] = ofctrl.NewController(localBridge)
		vdsOfControllerMap["policy"] = ofctrl.NewController(policyBridge)
		vdsOfControllerMap["cls"] = ofctrl.NewController(clsBridge)
		vdsOfControllerMap["uplink"] = ofctrl.NewController(uplinkBridge)
		datapathManager.ControllerMap[vdsID] = vdsOfControllerMap

		// initialize of swtich
		vdsOfSwitchMap := make(map[string]*ofctrl.OFSwitch)
		vdsOfSwitchMap["local"] = nil
		vdsOfSwitchMap["policy"] = nil
		vdsOfSwitchMap["cls"] = nil
		vdsOfSwitchMap["uplink"] = nil
		datapathManager.OfSwitchMap[vdsID] = vdsOfSwitchMap

		go vdsOfControllerMap["local"].Listen("0")
		go vdsOfControllerMap["policy"].Listen("0")
		go vdsOfControllerMap["cls"].Listen("0")
		go vdsOfControllerMap["uplink"].Listen("0")

		// initialize ovsdbDriver
		vdsOvsdbDriverMap := make(map[string]*ovsdbDriver.OvsDriver)
		vdsOvsdbDriverMap["local"] = ovsdbDriver.NewOvsDriver(localBridge.name)
		vdsOvsdbDriverMap["policy"] = ovsdbDriver.NewOvsDriver(policyBridge.name)
		vdsOvsdbDriverMap["cls"] = ovsdbDriver.NewOvsDriver(clsBridge.name)
		vdsOvsdbDriverMap["uplink"] = ovsdbDriver.NewOvsDriver(uplinkBridge.name)
		datapathManager.OvsdbDriverMap[vdsID] = vdsOvsdbDriverMap
		if err := datapathManager.OvsdbDriverMap[vdsID][LOCAL_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[LOCAL_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add local bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][POLICY_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[POLICY_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add policy bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][CLS_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[CLS_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add cls bridge controller to ovsdb, error: %v", err)
		}
		if err := datapathManager.OvsdbDriverMap[vdsID][UPLINK_BRIDGE_KEYWORD].AddController(LOOP_BACK_ADDR,
			uint16(vdsOfControllerMap[UPLINK_BRIDGE_KEYWORD].GetListenPort())); err != nil {
			log.Fatalf("Failed to add uplink bridge controller to ovsdb, error: %v", err)
		}

		vdsCount++
	}

	datapathManager.ofPortIpAddressUpdateChan = ofPortIpAddressUpdateChan

	return datapathManager
}

func (datapathManager *DatapathManager) InitializeDatapath() {
	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	var randID string
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		randID = vdsID
	}
	roundInfo, err := getRoundInfo(datapathManager.OvsdbDriverMap[randID]["local"])
	if err != nil {
		log.Fatalf("Failed to get Roundinfo from ovsdb: %v", err)
	}

	// Delete flow with curRoundNum cookie, for case: failed when restart process flow install.
	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		datapathManager.OfSwitchMap[vdsID]["local"].DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		datapathManager.OfSwitchMap[vdsID]["policy"].DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		datapathManager.OfSwitchMap[vdsID]["cls"].DeleteFlowByRoundInfo(roundInfo.curRoundNum)
		datapathManager.OfSwitchMap[vdsID]["uplink"].DeleteFlowByRoundInfo(roundInfo.curRoundNum)
	}

	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)

	for vdsID := range datapathManager.datapathConfig.ManagedVDSMap {
		datapathManager.OfSwitchMap[vdsID]["local"].CookieAllocator = cookieAllocator
		datapathManager.OfSwitchMap[vdsID]["policy"].CookieAllocator = cookieAllocator
		datapathManager.OfSwitchMap[vdsID]["cls"].CookieAllocator = cookieAllocator
		datapathManager.OfSwitchMap[vdsID]["uplink"].CookieAllocator = cookieAllocator

		datapathManager.BridgeChainMap[vdsID]["local"].BridgeInit()
		datapathManager.BridgeChainMap[vdsID]["policy"].BridgeInit()
		datapathManager.BridgeChainMap[vdsID]["cls"].BridgeInit()
		datapathManager.BridgeChainMap[vdsID]["uplink"].BridgeInit()

		// Delete flow with previousRoundNum cookie, and then persistent curRoundNum to ovsdb. We need to wait for long
		// enough to guarantee that all of the basic flow which we are still required updated with new roundInfo encoding to
		// flow cookie fields. But the time required to update all of the basic flow with updated roundInfo is
		// non-determined.
		// TODO  Implement a deterministic mechanism to control outdated flow flush procedure
		go func(vdsID string) {
			log.Infof("####### wait for flush previousRound flow from datapath")
			time.Sleep(time.Second * 15)

			datapathManager.OfSwitchMap[vdsID]["local"].DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
			datapathManager.OfSwitchMap[vdsID]["policy"].DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
			datapathManager.OfSwitchMap[vdsID]["cls"].DeleteFlowByRoundInfo(roundInfo.previousRoundNum)
			datapathManager.OfSwitchMap[vdsID]["uplink"].DeleteFlowByRoundInfo(roundInfo.previousRoundNum)

			err := persistentRoundInfo(roundInfo.curRoundNum, datapathManager.OvsdbDriverMap[vdsID]["local"])
			if err != nil {
				log.Fatalf("Failed to persistent roundInfo into ovsdb: %v", err)
			}
		}(vdsID)
	}
}

func (datapathManager *DatapathManager) WaitForBridgeConnected() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		if datapathManager.IsBridgesConnected() {
			return
		}
	}

	log.Fatalf("bridge chain Failed to connect")
}

func (datapathManager *DatapathManager) IsBridgesConnected() bool {
	var dpStatus bool = false

	for _, bridgeChain := range datapathManager.BridgeChainMap {
		if !bridgeChain["local"].IsSwitchConnected() {
			return dpStatus
		}
		if !bridgeChain["policy"].IsSwitchConnected() {
			return dpStatus
		}
		if !bridgeChain["cls"].IsSwitchConnected() {
			return dpStatus
		}
		if !bridgeChain["uplink"].IsSwitchConnected() {
			return dpStatus
		}
	}

	dpStatus = true

	return dpStatus
}

func (datapathManager *DatapathManager) AddLocalEndpoint(endpoint *Endpoint) error {
	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname == endpoint.BridgeName {
			if ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo)); ep != nil {
				log.Errorf("Already added local endpoint: %v", ep)
				return nil
			}

			err := datapathManager.BridgeChainMap[vdsID]["local"].AddLocalEndpoint(endpoint)
			if err != nil {
				log.Errorf("Failed to add local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)

				return fmt.Errorf("Failed to add local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
			}

			datapathManager.localEndpointDB.Set(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo), endpoint)
			break
		}
	}

	return nil
}

func (datapathManager *DatapathManager) UpdateLocalEndpoint() {
}

func (datapathManager *DatapathManager) RemoveLocalEndpoint(endpoint *Endpoint) error {
	for vdsID, ovsbrname := range datapathManager.datapathConfig.ManagedVDSMap {
		if ovsbrname != endpoint.BridgeName {
			continue
		}

		if ep, _ := datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo)); ep == nil {
			log.Errorf("Endpoint not found for %v-%v", ovsbrname, endpoint.PortNo)
			return nil
		}

		err := datapathManager.BridgeChainMap[vdsID]["local"].RemoveLocalEndpoint(endpoint)
		if err != nil {
			log.Errorf("Failed to remove local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)

			e := fmt.Errorf("Failed to remove local endpoint %v to vds %v : bridge %v, error: %v", endpoint.MacAddrStr, vdsID, ovsbrname, err)
			return e
		}

		datapathManager.localEndpointDB.Remove(fmt.Sprintf("%s-%d", ovsbrname, endpoint.PortNo))
		break
	}

	return nil
}

func (datapathManager *DatapathManager) AddEveroutePolicyRule(rule *EveroutePolicyRule, direction uint8, tier uint8) error {
	// check if we already have the rule
	datapathManager.ruleMux.RLock()
	if _, ok := datapathManager.Rules[rule.RuleId]; ok {
		oldRule := datapathManager.Rules[rule.RuleId].EveroutePolicyRule

		if RuleIsSame(oldRule, rule) {
			datapathManager.ruleMux.RUnlock()
			log.Infof("Rule already exists. new rule: {%+v}, old rule: {%+v}", rule, oldRule)
			return nil
		} else {
			datapathManager.ruleMux.RUnlock()
			log.Fatalf("Different rule %v and %v with same ruleId.", oldRule, rule)
			return nil
		}
	}
	datapathManager.ruleMux.RUnlock()

	log.Infof("Received AddRule: %+v", rule)
	ruleFlowMap := make(map[string]*ofctrl.Flow)
	// Install policy rule flow to datapath
	for vdsID, bridgeChain := range datapathManager.BridgeChainMap {
		ruleFlow, err := bridgeChain["policy"].AddMicroSegmentRule(rule, direction, tier)
		if err != nil {
			log.Errorf("Failed to add microsegment rule to vdsID %v, bridge %s, error: %v", vdsID, bridgeChain["policy"], err)
			return err
		}
		ruleFlowMap[vdsID] = ruleFlow
	}

	// save the rule. ruleFlowMap need deepcopy, NOTE
	pRule := EveroutePolicyRuleEntry{
		EveroutePolicyRule: rule,
		RuleFlowMap:        ruleFlowMap,
	}
	datapathManager.ruleMux.Lock()
	datapathManager.Rules[rule.RuleId] = &pRule
	datapathManager.ruleMux.Unlock()

	return nil
}

func (datapathManager *DatapathManager) RemoveEveroutePolicyRule(rule *EveroutePolicyRule) error {
	datapathManager.ruleMux.Lock()
	defer datapathManager.ruleMux.Unlock()

	for vdsID, _ := range datapathManager.BridgeChainMap {

		pRule := datapathManager.Rules[rule.RuleId]
		if pRule == nil {
			return fmt.Errorf("Rule %v not found when deleting", rule)
		}

		err := pRule.RuleFlowMap[vdsID].Delete()
		if err != nil {
			return fmt.Errorf("Failed to delete flow for rule: %+v. Err: %v", rule, err)
		}
	}

	delete(datapathManager.Rules, rule.RuleId)

	return nil
}

func RuleIsSame(r1, r2 *EveroutePolicyRule) bool {
	return reflect.DeepEqual(*r1, *r2)
}

func DeepCopyMap(theMap interface{}) interface{} {
	maptype := reflect.TypeOf(theMap)

	srcMap := reflect.ValueOf(theMap)
	dstMap := reflect.MakeMapWithSize(maptype, srcMap.Len())

	for _, key := range srcMap.MapKeys() {
		dstMap.SetMapIndex(key, srcMap.MapIndex(key))
	}
	return dstMap.Interface()
}

// func getRoundInfo(ovsdbDriver *ovsdbDriver.OvsDriver) (*RoundInfo, error) {
// 	var num uint64
// 	var err error

// 	externalIds, err := ovsdbDriver.GetExternalIds()
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to get ovsdb externalids: %v", err)
// 	}

// 	if len(externalIds) == 0 {
// 		log.Infof("Bridge's external-ids are empty")
// 		return &RoundInfo{
// 			curRoundNum: uint64(1),
// 		}, nil
// 	}

// 	roundNum, exists := externalIds[OfnetRestartRound]
// 	if !exists {
// 		log.Infof("Bridge's external-ids don't contain ofnetRestartRound field")
// 		return &RoundInfo{
// 			curRoundNum: uint64(1),
// 		}, nil
// 	}

// 	num, err = strconv.ParseUint(roundNum, 10, 64)
// 	if err != nil {
// 		return nil, fmt.Errorf("Bad format of round number: %+v, parse error: %+v", roundNum, err)
// 	}

// 	return &RoundInfo{
// 		previousRoundNum: num,
// 		curRoundNum:      num + 1,
// 	}, nil
// }

// func persistentRoundInfo(curRoundNum uint64, ovsdbDriver *ovsdbDriver.OvsDriver) error {
// 	externalIds, err := ovsdbDriver.GetExternalIds()
// 	if err != nil {
// 		return err
// 	}

// 	externalIds[OfnetRestartRound] = fmt.Sprint(curRoundNum)

// 	return ovsdbDriver.SetExternalIds(externalIds)
// }
