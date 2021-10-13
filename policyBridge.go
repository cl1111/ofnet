package ofnet

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"

	"github.com/contiv/ofnet/ofctrl"
	// "github.com/contiv/ofnet/ofctrl/cookie"
)

const (
	INPUT_TABLE               = 0
	CT_STATE_TABLE            = 1
	DIRECTION_SELECTION_TABLE = 10
	EGRESS_TIER1_TABLE        = 20
	EGRESS_TIER2_TABLE        = 25
	EGRESS_TIER3_TABLE        = 30
	INGRESS_TIER1_TABLE       = 50
	INGRESS_TIER2_TABLE       = 55
	INGRESS_TIER3_TABLE       = 60
	CT_COMMIT_TABLE           = 70
	SFC_POLICY_TABLE          = 80
	POLICY_FORWARDING_TABLE   = 90
)

type PolicyBridge struct {
	name            string
	datapathManager *DatapathManager
	ofSwitch        *ofctrl.OFSwitch
	controller      *ofctrl.Controller

	inputTable              *ofctrl.Table
	ctStateTable            *ofctrl.Table
	directionSelectionTable *ofctrl.Table
	egressTier1PolicyTable  *ofctrl.Table
	egressTier2PolicyTable  *ofctrl.Table
	egressTier3PolicyTable  *ofctrl.Table
	ingressTier1PolicyTable *ofctrl.Table
	ingressTier2PolicyTable *ofctrl.Table
	ingressTier3PolicyTable *ofctrl.Table
	ctCommitTable           *ofctrl.Table
	sfcPolicyTable          *ofctrl.Table
	policyForwardingTable   *ofctrl.Table
	ouputTable              *ofctrl.Table

	inputIpRedirectFlow   *ofctrl.Flow
	inputFromLocalFlow    *ofctrl.Flow
	inputFromUpstreamFlow *ofctrl.Flow
	inputDefaultFlow      *ofctrl.Flow

	ctStateFlow        *ofctrl.Flow
	ctInvFlow          *ofctrl.Flow
	ctStateDefaultFlow *ofctrl.Flow

	fromLocalToEgressFlow     *ofctrl.Flow
	formUpstreamToIngressFlow *ofctrl.Flow

	egressTier1PolicyFlow  []*ofctrl.Flow
	egressTier2PolicyFlow  []*ofctrl.Flow
	egressTier3PolicyFlow  []*ofctrl.Flow
	ingressTier1PolicyFlow []*ofctrl.Flow
	ingressTier2PolicyFlow []*ofctrl.Flow
	ingressTier3PolicyFlow []*ofctrl.Flow

	ctCommitFlow             *ofctrl.Flow
	ctCommitTableDefaultFlow *ofctrl.Flow

	fromLocalOutputFlow    *ofctrl.Flow
	fromUpstreamOuputFlow  *ofctrl.Flow
	outputTableDefaultFlow *ofctrl.Flow

	policySwitchStatusMutex sync.RWMutex
	isPolicySwitchConnected bool
}

func NewPolicyBridge(brName string, datapathManager *DatapathManager) *PolicyBridge {
	policyBridge := new(PolicyBridge)
	policyBridge.name = fmt.Sprintf("%s-policy", brName)
	policyBridge.datapathManager = datapathManager
	return policyBridge
}

func (p *PolicyBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", p.name)

	p.ofSwitch = sw
	vdsname := strings.Split(p.name, "-")[0]
	p.datapathManager.OfSwitchMap[vdsname]["policy"] = sw

	p.policySwitchStatusMutex.Lock()
	p.isPolicySwitchConnected = true
	p.policySwitchStatusMutex.Unlock()
}

func (p *PolicyBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", p.name)
	p.policySwitchStatusMutex.Lock()
	p.isPolicySwitchConnected = false
	p.policySwitchStatusMutex.Unlock()

	p.ofSwitch = nil
}

func (p *PolicyBridge) IsSwitchConnected() bool {
	p.policySwitchStatusMutex.Lock()
	defer p.policySwitchStatusMutex.Unlock()

	return p.isPolicySwitchConnected
}

func (p *PolicyBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		p.policySwitchStatusMutex.Lock()
		if p.isPolicySwitchConnected {
			p.policySwitchStatusMutex.Unlock()
			return
		}
		p.policySwitchStatusMutex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", p.name)
}

func (p *PolicyBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
}

func (p *PolicyBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (p *PolicyBridge) BridgeInit() error {
	log.Infof("init policy bridge")
	sw := p.ofSwitch

	p.inputTable = sw.DefaultTable()
	p.ctStateTable, _ = sw.NewTable(CT_STATE_TABLE)
	p.directionSelectionTable, _ = sw.NewTable(DIRECTION_SELECTION_TABLE)
	p.ingressTier1PolicyTable, _ = sw.NewTable(INGRESS_TIER1_TABLE)
	p.ingressTier2PolicyTable, _ = sw.NewTable(INGRESS_TIER2_TABLE)
	p.ingressTier3PolicyTable, _ = sw.NewTable(INGRESS_TIER3_TABLE)
	p.egressTier1PolicyTable, _ = sw.NewTable(EGRESS_TIER1_TABLE)
	p.egressTier2PolicyTable, _ = sw.NewTable(EGRESS_TIER2_TABLE)
	p.egressTier3PolicyTable, _ = sw.NewTable(EGRESS_TIER3_TABLE)
	p.ctCommitTable, _ = sw.NewTable(CT_COMMIT_TABLE)
	p.sfcPolicyTable, _ = sw.NewTable(SFC_POLICY_TABLE)
	p.policyForwardingTable, _ = sw.NewTable(POLICY_FORWARDING_TABLE)

	// Table 0, inputTable ip redirect flow
	var ctStateTableId uint8 = CT_STATE_TABLE
	var policyConntrackZone uint16 = 65520
	ctAction := ofctrl.NewConntrackAction(false, false, &ctStateTableId, &policyConntrackZone)
	inputIpRedirectFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY,
		Ethertype: 0x0800,
	})
	inputIpRedirectFlow.SetConntrack(ctAction)

	// Table 0, from local bridge flow
	inputFromLocalFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY - FLOW_MATCH_OFFSET,
		InputPort: uint32(POLICY_TO_LOCAL_PORT),
	})
	outputPort, _ := p.ofSwitch.OutputPort(POLICY_TO_CLS_PORT)
	inputFromLocalFlow.Next(outputPort)

	// Table 0, from cls bridge flow
	inputFromUpstreamFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority:  HIGH_MATCH_FLOW_PRIORITY - FLOW_MATCH_OFFSET,
		InputPort: uint32(POLICY_TO_CLS_PORT),
	})
	outputPort, _ = p.ofSwitch.OutputPort(POLICY_TO_LOCAL_PORT)
	inputFromUpstreamFlow.Next(outputPort)

	// Table 0, default flow
	inputDefaultFlow, _ := p.inputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	inputDefaultFlow.Next(p.ofSwitch.DropAction())

	// Table 1, ctState table, est state flow
	ceEstState := openflow13.NewCTStates()
	ceEstState.UnsetNew()
	ceEstState.SetEst()
	ctStateFlow, _ := p.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY,
		CtStates: ceEstState,
	})
	ctStateFlow.Next(p.ctCommitTable)

	// Table 1, ctState table, invlid state flow
	ctInvState := openflow13.NewCTStates()
	ctInvState.SetInv()
	ctInvState.SetTrk()
	ctInvFlow, _ := p.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority: MID_MATCH_FLOW_PRIORITY - FLOW_MATCH_OFFSET,
		CtStates: ctInvState,
	})
	ctInvFlow.Next(p.ofSwitch.DropAction())

	// Table 1. default flow
	ctStateDefaultFlow, _ := p.ctStateTable.NewFlow(ofctrl.FlowMatch{
		Priority:  DEFAULT_FLOW_PRIORITY,
		Ethertype: 0x0800,
	})
	ctStateDefaultFlow.Next(p.directionSelectionTable)

	// directionSelectiontable
	fromLocalToEgressFlow, _ := p.directionSelectionTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: uint32(POLICY_TO_LOCAL_PORT),
	})
	fromLocalToEgressFlow.Next(p.egressTier1PolicyTable)

	fromUpstreamToIngressFlow, _ := p.directionSelectionTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		InputPort: uint32(POLICY_TO_CLS_PORT),
	})
	fromUpstreamToIngressFlow.Next(p.ingressTier1PolicyTable)

	// TODO vnf instance selection

	// egress policy table
	egressTier1DefaultFlow, _ := p.egressTier1PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	egressTier1DefaultFlow.Next(p.egressTier2PolicyTable)

	egressTier2DefaultFlow, _ := p.egressTier2PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	egressTier2DefaultFlow.Next(p.egressTier3PolicyTable)

	egressTier3DefaultFlow, _ := p.egressTier3PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	egressTier3DefaultFlow.Next(p.ctCommitTable)

	// ingress policy table
	ingressTier1DefaultFlow, _ := p.ingressTier1PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	ingressTier1DefaultFlow.Next(p.ingressTier2PolicyTable)

	ingressTier2DefaultFlow, _ := p.ingressTier2PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	ingressTier2DefaultFlow.Next(p.ingressTier3PolicyTable)

	ingressTier3DefaultFlow, _ := p.ingressTier3PolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	ingressTier3DefaultFlow.Next(p.ctCommitTable)

	// conntrack commit table
	ctTrkState := openflow13.NewCTStates()
	ctTrkState.SetNew()
	ctTrkState.SetTrk()
	ctCommitFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		Ethertype: 0x0800,
		CtStates:  ctTrkState,
	})
	var sfcPolicyTable uint8 = SFC_POLICY_TABLE
	ctCommitAction := ofctrl.NewConntrackAction(true, false, &sfcPolicyTable, &policyConntrackZone)
	ctCommitFlow.SetConntrack(ctCommitAction)

	ctCommitTableDefaultFlow, _ := p.ctCommitTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	ctCommitTableDefaultFlow.Next(p.sfcPolicyTable)

	// sfc policy table
	sfcPolicyTableDefaultFlow, _ := p.sfcPolicyTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY - 3,
	})
	sfcPolicyTableDefaultFlow.Next(p.policyForwardingTable)

	// policy forwarding table
	fromLocalOutputFlow, _ := p.policyForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: uint32(POLICY_TO_LOCAL_PORT),
		Regs: []*ofctrl.NXRegister{
			{
				RegID: 6,
				Data:  0,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ = p.ofSwitch.OutputPort(POLICY_TO_CLS_PORT)
	fromLocalOutputFlow.Next(outputPort)

	fromUpstreamOuputFlow, _ := p.policyForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: uint32(POLICY_TO_CLS_PORT),
		Regs: []*ofctrl.NXRegister{
			{
				RegID: 6,
				Data:  0,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ = p.ofSwitch.OutputPort(POLICY_TO_LOCAL_PORT)
	fromUpstreamOuputFlow.Next(outputPort)

	return nil
}

func (p *PolicyBridge) BridgeReset() error {
	return nil
}

func (p *PolicyBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (p *PolicyBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (p *PolicyBridge) GetTierTable(direction uint8, tier uint8) (*ofctrl.Table, *ofctrl.Table, error) {
	var policyTable, nextTable *ofctrl.Table
	switch direction {
	case POLICY_DIRECTION_OUT:
		switch tier {
		case POLICY_TIER0:
			policyTable = p.egressTier1PolicyTable
			nextTable = p.egressTier2PolicyTable
		case POLICY_TIER1:
			policyTable = p.egressTier2PolicyTable
			nextTable = p.egressTier3PolicyTable
		case POLICY_TIER2:
			policyTable = p.egressTier3PolicyTable
			nextTable = p.ctCommitTable
		default:
			return nil, nil, errors.New("unknow policy tier")
		}
	case POLICY_DIRECTION_IN:
		switch tier {
		case POLICY_TIER0:
			policyTable = p.ingressTier1PolicyTable
			nextTable = p.ingressTier2PolicyTable
		case POLICY_TIER1:
			policyTable = p.ingressTier2PolicyTable
			nextTable = p.ingressTier3PolicyTable
		case POLICY_TIER2:
			policyTable = p.ingressTier3PolicyTable
			nextTable = p.ctCommitTable
		default:
			return nil, nil, errors.New("unknow policy tier")
		}
	}

	return policyTable, nextTable, nil
}

func (p *PolicyBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*ofctrl.Flow, error) {
	var ipDa *net.IP = nil
	var ipDaMask *net.IP = nil
	var ipSa *net.IP = nil
	var ipSaMask *net.IP = nil
	var err error

	// make sure switch is connected
	if !p.isPolicySwitchConnected {
		p.WaitForSwitchConnection()
	}

	// Different tier have different nextTable select strategy:
	policyTable, nextTable, e := p.GetTierTable(direction, tier)
	if e != nil {
		log.Errorf("Failed to get policy table tier %v", tier)
		return nil, errors.New("Failed get policy table")
	}

	// Parse dst ip
	if rule.DstIpAddr != "" {
		ipDa, ipDaMask, err = ParseIPAddrMaskString(rule.DstIpAddr)
		if err != nil {
			log.Errorf("Failed to parse dst ip %s. Err: %v", rule.DstIpAddr, err)
			return nil, err
		}
	}

	// parse src ip
	if rule.SrcIpAddr != "" {
		ipSa, ipSaMask, err = ParseIPAddrMaskString(rule.SrcIpAddr)
		if err != nil {
			log.Errorf("Failed to parse src ip %s. Err: %v", rule.SrcIpAddr, err)
			return nil, err
		}
	}

	// Install the rule in policy table
	ruleFlow, err := policyTable.NewFlow(ofctrl.FlowMatch{
		Priority:   uint16(FLOW_POLICY_PRIORITY_OFFSET + rule.Priority),
		Ethertype:  0x0800,
		IpDa:       ipDa,
		IpDaMask:   ipDaMask,
		IpSa:       ipSa,
		IpSaMask:   ipSaMask,
		IpProto:    rule.IpProtocol,
		TcpSrcPort: rule.SrcPort,
		TcpDstPort: rule.DstPort,
		UdpSrcPort: rule.SrcPort,
		UdpDstPort: rule.DstPort,
	})
	if err != nil {
		log.Errorf("Failed to add flow for rule {%v}. Err: %v", rule, err)
		return nil, err
	}

	// Point it to next table
	if rule.Action == "allow" {
		err = ruleFlow.Next(nextTable)
		if err != nil {
			log.Errorf("Failed to install flow {%+v}. Err: %v", ruleFlow, err)
			return nil, err
		}
	} else if rule.Action == "deny" {
		err = ruleFlow.Next(p.ofSwitch.DropAction())
		if err != nil {
			log.Errorf("Failed to install flow {%+v}. Err: %v", ruleFlow, err)
			return nil, err
		}
	} else {
		log.Errorf("Unknown action in rule {%+v}", rule)
		return nil, errors.New("Unknown action in rule")
	}

	return ruleFlow, nil
}

func (p *PolicyBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

func (p *PolicyBridge) AddVNFInstance() error {
	return nil
}

func (p *PolicyBridge) RemoveVNFInstance() error {
	return nil
}

func (p *PolicyBridge) AddSFCRule() error {
	return nil
}

func (p *PolicyBridge) RemoveSFCRule() error {
	return nil
}
