package ofnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/protocol"

	"github.com/contiv/ofnet/ofctrl"
)

const (
	VLAN_INPUT_TABLE           = 0
	L2_FORWARDING_TABLE        = 5
	L2_LEARNING_TABLE          = 10
	UNTAGGED_L2_LEARNING_TABLE = 11
	FROM_LOCAL_REDIRECT_TABLE  = 15
)

type LocalBridge struct {
	name            string
	datapathManager *DatapathManager
	ofSwitch        *ofctrl.OFSwitch
	controller      *ofctrl.Controller

	vlanInputTable                       *ofctrl.Table // Table 0
	localEndpointL2ForwardingTable       *ofctrl.Table // Table 5
	localEndpointL2LearningTable         *ofctrl.Table // table 10
	untaggedLocalEndpointL2LearningTable *ofctrl.Table
	fromLocalRedirectTable               *ofctrl.Table // Table 15

	// Table 0
	fromLocalEndpointFlow     map[uint32]*ofctrl.Flow // map local endpoint interface ofport to its fromLocalEndpointFlow
	fromUpstreamFlow          *ofctrl.Flow
	vlanInputTableDefaultFlow *ofctrl.Flow

	// Table 5
	toLocalEndpointFlow   *ofctrl.Flow // learned to localEndpoint flow
	localToLocalBUMFlow   map[uint32]*ofctrl.Flow
	defaultForwardingFlow *ofctrl.Flow

	// Table 10
	l2LearningFlow *ofctrl.Flow

	// Table 15
	fromLocalArpRedirectFlow *ofctrl.Flow
	fromLocalRedirectFlow    *ofctrl.Flow

	localSwitchStatusMuxtex sync.RWMutex
	isLocalSwitchConnected  bool
}

func NewLocalBridge(brName string, datapathManager *DatapathManager) *LocalBridge {
	localBridge := new(LocalBridge)
	localBridge.name = brName
	localBridge.datapathManager = datapathManager
	localBridge.fromLocalEndpointFlow = make(map[uint32]*ofctrl.Flow)
	localBridge.localToLocalBUMFlow = make(map[uint32]*ofctrl.Flow)

	return localBridge
}

// Controller interface
func (l *LocalBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", l.name)

	vdsname := strings.Split(l.name, "-")[0]
	l.datapathManager.OfSwitchMap[vdsname]["local"] = sw
	l.ofSwitch = sw

	l.localSwitchStatusMuxtex.Lock()
	l.isLocalSwitchConnected = true
	l.localSwitchStatusMuxtex.Unlock()
}

func (l *LocalBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", l.name)
	l.localSwitchStatusMuxtex.Lock()
	l.isLocalSwitchConnected = false
	l.localSwitchStatusMuxtex.Unlock()

	l.ofSwitch = nil
}

func (l *LocalBridge) IsSwitchConnected() bool {
	l.localSwitchStatusMuxtex.Lock()
	defer l.localSwitchStatusMuxtex.Unlock()

	return l.isLocalSwitchConnected
}

func (l *LocalBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		l.localSwitchStatusMuxtex.Lock()
		if l.isLocalSwitchConnected {
			l.localSwitchStatusMuxtex.Unlock()
			return
		}
		l.localSwitchStatusMuxtex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", l.name)
}

func (l *LocalBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
	switch pkt.Data.Ethertype {
	case 0x0806:
		if (pkt.Match.Type == openflow13.MatchType_OXM) &&
			(pkt.Match.Fields[0].Class == openflow13.OXM_CLASS_OPENFLOW_BASIC) &&
			(pkt.Match.Fields[0].Field == openflow13.OXM_FIELD_IN_PORT) {
			// Get the input port number
			switch t := pkt.Match.Fields[0].Value.(type) {
			case *openflow13.InPortField:
				var inPortFld openflow13.InPortField
				inPortFld = *t
				l.processArp(pkt.Data, inPortFld.InPort)
			}
		}
	case protocol.IPv4_MSG: // other type of packet that must processing by controller
		log.Errorf("controller received non arp packet error.")
		return
	}
}

func (l *LocalBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (l *LocalBridge) processArp(pkt protocol.Ethernet, inPort uint32) {
	switch t := pkt.Data.(type) {
	case *protocol.ARP:
		var arpIn protocol.ARP = *t
		// log.Infof("##### inputPort : %v, controller received arp packet: %v", inPort, arpIn)

		ofPortUpdatedPort, ipAddrUpdatedPort := l.filterUpdatedLocalEndpointOfPort(arpIn, inPort)

		// Don't add endpoint from received arp pkt event. We just add local endpoint from control-plane
		// Already exists endpoint

		if ofPortUpdatedPort != nil {
			l.localEndpointOfPortUpdate(*ofPortUpdatedPort, inPort, arpIn)
		}

		if ipAddrUpdatedPort != nil {
			l.localEndpointIpAddrUpdate(*ipAddrUpdatedPort, inPort, arpIn)
		}

		// NOTE output to local-to-policy-patch port
		l.arpOutput(pkt, inPort, uint32(LOCAL_TO_POLICY_PORT))
	}
}

func (l *LocalBridge) filterUpdatedLocalEndpointOfPort(arpIn protocol.ARP, inPort uint32) (*uint32, *uint32) {
	var ofPort uint32

	for endpointObj := range l.datapathManager.localEndpointDB.IterBuffered() {
		endpoint := endpointObj.Val.(*Endpoint)

		if endpoint.MacAddrStr == arpIn.HWSrc.String() && endpoint.PortNo != inPort {

			ofPort = endpoint.PortNo

			return &ofPort, nil
		}

		if endpoint.MacAddrStr == arpIn.HWSrc.String() && endpoint.PortNo == inPort &&
			!endpoint.IPAddr.Equal(arpIn.IPSrc) {

			ofPort = endpoint.PortNo

			return nil, &ofPort
		}
	}

	return nil, nil

}

func (l *LocalBridge) localEndpointOfPortUpdate(ofPortUpdatedPort uint32, inPort uint32, arpIn protocol.ARP) {
	endpointObj, _ := l.datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", l.name, ofPortUpdatedPort))
	if endpointObj == nil {
		log.Errorf("OfPort %d on bridge %s related Endpoint was not found", ofPortUpdatedPort, l.name)
		return
	}
	endpoint := endpointObj.(*Endpoint)

	log.Infof("Update localOfPort's endpointInfo from %d : %v to %d : %v", ofPortUpdatedPort,
		endpoint.IPAddr, inPort, arpIn.IPSrc)

	l.notifyLocalEndpointInfoUpdate(arpIn, ofPortUpdatedPort, true)

	l.updateLocalEndpointInfoEntry(arpIn, inPort)
	l.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)

}

func (l *LocalBridge) localEndpointIpAddrUpdate(ipAddrUpdatedPort uint32, inPort uint32, arpIn protocol.ARP) {
	endpointObj, _ := l.datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", l.name, ipAddrUpdatedPort))
	if endpointObj == nil {
		log.Errorf("OfPort: %d related Endpoint was not found", ipAddrUpdatedPort)
		return
	}

	endpoint := endpointObj.(*Endpoint)
	log.Infof("Update ip address of local endpoint with ofPort %d from %v to %v.", ipAddrUpdatedPort,
		endpoint.IPAddr, arpIn.IPSrc)

	l.updateLocalEndpointInfoEntry(arpIn, inPort)
	l.notifyLocalEndpointInfoUpdate(arpIn, inPort, false)

}

func (l *LocalBridge) notifyLocalEndpointInfoUpdate(arpIn protocol.ARP, ofPort uint32, isDelete bool) {
	updatedOfPortInfo := make(map[string][]net.IP)
	if isDelete {
		updatedOfPortInfo[fmt.Sprintf("%s-%d", l.name, ofPort)] = []net.IP{}
	} else {
		updatedOfPortInfo[fmt.Sprintf("%s-%d", l.name, ofPort)] = []net.IP{arpIn.IPSrc}
	}
	l.datapathManager.ofPortIpAddressUpdateChan <- updatedOfPortInfo
}

func (l *LocalBridge) updateLocalEndpointInfoEntry(arpIn protocol.ARP, ofPort uint32) {
	endpointObj, _ := l.datapathManager.localEndpointDB.Get(fmt.Sprintf("%s-%d", l.name, ofPort))
	if endpointObj == nil {
		err := fmt.Errorf("Endpoint not found for port %d\n", ofPort)
		log.Error(err)
		return
	}

	endpoint := endpointObj.(*Endpoint)

	// Update endpoint ip in localEndpointDb
	learnedIp := make(net.IP, len(arpIn.IPSrc))
	copy(learnedIp, arpIn.IPSrc)
	ep := &Endpoint{
		IPAddr:     learnedIp,
		MacAddrStr: endpoint.MacAddrStr,
		VlanID:     endpoint.VlanID,
		PortNo:     ofPort,
		BridgeName: l.name,
	}
	// copy(endpoint.IPAddr, arpIn.IPSrc)
	// endpoint.PortNo = ofPort
	l.datapathManager.localEndpointDB.Set(fmt.Sprintf("%s-%d", l.name, ofPort), ep)
}

func (l *LocalBridge) arpOutput(pkt protocol.Ethernet, inPort uint32, outputPort uint32) {
	arpIn := pkt.Data.(*protocol.ARP)

	ethPkt := protocol.NewEthernet()
	ethPkt.VLANID = pkt.VLANID
	ethPkt.HWDst = pkt.HWDst
	ethPkt.HWSrc = pkt.HWSrc
	ethPkt.Ethertype = 0x0806
	ethPkt.Data = arpIn

	pktOut := openflow13.NewPacketOut()
	pktOut.InPort = inPort
	pktOut.Data = ethPkt
	pktOut.AddAction(openflow13.NewActionOutput(outputPort))
	// pktOut.AddAction(openflow13.NewActionOutput(openflow13.P_NORMAL))

	l.ofSwitch.Send(pktOut)
	log.Infof("$$$$$$ send learned arp packet : %v to %v", pkt, outputPort)
}

// TODO learned local endpoint sync

// specific type Bridge interface
func (l *LocalBridge) BridgeInit() error {
	log.Infof("init local bridge")
	l.vlanInputTable = l.ofSwitch.DefaultTable()
	l.localEndpointL2ForwardingTable, _ = l.ofSwitch.NewTable(L2_FORWARDING_TABLE)
	l.localEndpointL2LearningTable, _ = l.ofSwitch.NewTable(L2_LEARNING_TABLE)
	l.untaggedLocalEndpointL2LearningTable, _ = l.ofSwitch.NewTable(UNTAGGED_L2_LEARNING_TABLE)
	l.fromLocalRedirectTable, _ = l.ofSwitch.NewTable(FROM_LOCAL_REDIRECT_TABLE)

	// vlanInput table
	fromUpstreamFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: uint32(LOCAL_TO_POLICY_PORT),
	})
	fromUpstreamFlow.Next(l.localEndpointL2ForwardingTable)

	vlanInputTableDefaultFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	vlanInputTableDefaultFlow.Next(l.ofSwitch.DropAction())

	// l2 forwarding table
	localToLocalBUMDefaultFlow, _ := l.localEndpointL2ForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	outputPort, _ := l.ofSwitch.OutputPort(openflow13.P_ALL)
	localToLocalBUMDefaultFlow.Next(outputPort)

	// l2 learning table
	// NOTE whether cookie id need to be sync
	l2LearningFlow, _ := l.localEndpointL2LearningTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})

	fromLocalLearnAction := ofctrl.NewLearnAction(L2_FORWARDING_TABLE, MID_MATCH_FLOW_PRIORITY+3, 0, 0, 0, 0, 0)

	learnDstMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnSrcMatchField1 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnDstMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_dst",
		Start: 0,
	}
	learnSrcMatchField2 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_src",
		Start: 0,
	}

	err := fromLocalLearnAction.AddLearnedMatch(learnDstMatchField1, 12, learnSrcMatchField1, nil)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedMatch nxm_of_vlan_tci failure, error: %v", err)
	}
	err = fromLocalLearnAction.AddLearnedMatch(learnDstMatchField2, 48, learnSrcMatchField2, nil)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedMatch nxm_of_eth_dst failure, error: %v", err)
	}

	srcValue := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue, uint16(0))
	err = fromLocalLearnAction.AddLearnedLoadAction(&ofctrl.LearnField{Name: "nxm_of_vlan_tci", Start: 0}, 12, nil, srcValue)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedLoadAction: load:0x0->NXM_OF_vlan_tci[] failure, error: %v", err)
	}
	err = fromLocalLearnAction.AddLearnedOutputAction(&ofctrl.LearnField{Name: "nxm_of_in_port", Start: 0}, 16)
	if err != nil {
		log.Fatalf("Failed to initialize learn action: AddLearnedOutputAction output:nxm_of_in_port failure, error: %v", err)
	}

	l2LearningFlow.Learn(fromLocalLearnAction)
	l2LearningFlow.Next(ofctrl.NewEmptyElem())

	// Table 6 from local redirect flow
	fromLocalArpRedirectFlow, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: 0x0806,
	})
	fromLocalArpRedirectFlow.Next(l.ofSwitch.SendToController())

	fromLocalRedirectFlow, _ := l.fromLocalRedirectTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
	})
	outputPort, _ = l.ofSwitch.OutputPort(LOCAL_TO_POLICY_PORT)
	fromLocalRedirectFlow.Next(outputPort)

	return nil
}

func (l *LocalBridge) BridgeReset() error {
	return nil
}

func (l *LocalBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	// Table 0, from local endpoint
	var vlanIdMask uint16 = 0x1fff
	vlanInputTableFromLocalFlow, _ := l.vlanInputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: endpoint.PortNo,
	})
	vlanInputTableFromLocalFlow.LoadField("nxm_of_vlan_tci", uint64(endpoint.VlanID), openflow13.NewNXRange(0, 11))
	vlanInputTableFromLocalFlow.Resubmit(nil, &l.localEndpointL2LearningTable.TableId)
	vlanInputTableFromLocalFlow.Resubmit(nil, &l.fromLocalRedirectTable.TableId)
	vlanInputTableFromLocalFlow.Next(ofctrl.NewEmptyElem())
	log.Infof("add from local endpoint flow: %v", vlanInputTableFromLocalFlow)
	l.fromLocalEndpointFlow[endpoint.PortNo] = vlanInputTableFromLocalFlow

	// Table 1, from local to local bum redirect flow
	log.Infof("###### added local endpoint vlanid: %v", endpoint.VlanID)
	endpointMac, _ := net.ParseMAC(endpoint.MacAddrStr)
	localToLocalBUMFlow, _ := l.localEndpointL2ForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:   MID_MATCH_FLOW_PRIORITY,
		MacSa:      &endpointMac,
		VlanId:     endpoint.VlanID,
		VlanIdMask: &vlanIdMask,
	})
	localToLocalBUMFlow.LoadField("nxm_of_vlan_tci", 0, openflow13.NewNXRange(0, 12))
	localToLocalBUMFlow.LoadField("nxm_of_in_port", uint64(endpoint.PortNo), openflow13.NewNXRange(0, 15))
	localToLocalBUMFlow.Next(l.ofSwitch.NormalLookup())
	log.Infof("add local to local flow: %v", localToLocalBUMFlow)
	l.localToLocalBUMFlow[endpoint.PortNo] = localToLocalBUMFlow

	flowCacheEntryMap := flowCacheEntryMap{}
	log.Infof("###### vlan input from local endpoint flow match: %v", vlanInputTableFromLocalFlow.Match)
	flowCacheEntryMap[vlanInputTableFromLocalFlow.FlowKey()] = vlanInputTableFromLocalFlow
	log.Infof("###### local to local bum flow match: %v", localToLocalBUMFlow.Match)
	flowCacheEntryMap[localToLocalBUMFlow.FlowKey()] = localToLocalBUMFlow
	l.datapathManager.localEndpointFlowCache.Store(fmt.Sprintf("%s-%d", l.name, endpoint.PortNo), flowCacheEntryMap)

	return nil
}

func (l *LocalBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	// remove table 0 from local endpoing flow
	if err := l.fromLocalEndpointFlow[endpoint.PortNo].Delete(); err != nil {
		log.Errorf("Failed to delete from local endpoint flow for endpoint: %v, error: %v", *endpoint, err)
	}
	delete(l.fromLocalEndpointFlow, endpoint.PortNo)

	if err := l.localToLocalBUMFlow[endpoint.PortNo].Delete(); err != nil {
		log.Errorf("Failed to delete local to local bum flow for endpoint: %v, error: %v", *endpoint, err)
	}
	delete(l.localToLocalBUMFlow, endpoint.PortNo)

	// remote table 1 local to local bum redirect flow
	l.datapathManager.localEndpointFlowCache.Delete(fmt.Sprintf("%s-%d", l.name, endpoint.PortNo))
	return nil
}

func (p *LocalBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*ofctrl.Flow, error) {
	return nil, nil
}

func (l *LocalBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

func (l *LocalBridge) AddVNFInstance() error {
	return nil
}

func (l *LocalBridge) RemoveVNFInstance() error {
	return nil
}

func (l *LocalBridge) AddSFCRule() error {
	return nil
}

func (l *LocalBridge) RemoveSFCRule() error {
	return nil
}
