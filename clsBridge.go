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

	"github.com/contiv/ofnet/ofctrl"
)

const (
	CLSBRIDGE_LEARNING_TABLE_ID   = 0
	CLSBRIDGE_FORWARDING_TABLE_ID = 2
	CLSBRIDGE_OUTPUT_TABLE_ID     = 3
)

const (
	BROADCAST_MAC_ADDRESS_MASK = "01:00:00:00:00:00"
)

type ClsBridge struct {
	name            string
	controller      *ofctrl.Controller
	datapathManager *DatapathManager
	ofSwitch        *ofctrl.OFSwitch

	clsBridgeLearningTable   *ofctrl.Table
	clsBridgeForwardingTable *ofctrl.Table
	clsBridgeOutputTable     *ofctrl.Table

	fromUplinkLearningFlow   *ofctrl.Flow
	fromLocalLearningFlow    *ofctrl.Flow
	learningTableDefaultFlow *ofctrl.Flow

	fromLocalBroadcastMarkFlow *ofctrl.Flow
	unlearnedFlow              *ofctrl.Flow

	floodingOutputFlow            *ofctrl.Flow
	learnedLocalToLocalOutputFlow *ofctrl.Flow
	learnedLocalToRemoteOuputFlow *ofctrl.Flow
	outputTableDefaultFlow        *ofctrl.Flow

	clsSwitchStatusMutex sync.RWMutex
	isClsSwitchConnected bool
}

func NewClsBridge(brName string, datapathManager *DatapathManager) *ClsBridge {
	clsBridge := new(ClsBridge)
	clsBridge.name = fmt.Sprintf("%s-cls", brName)
	clsBridge.datapathManager = datapathManager

	return clsBridge
}

func (c *ClsBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", c.name)

	c.ofSwitch = sw
	log.Infof("cls switch connected : %v, $$$$ c.name", c.datapathManager.OfSwitchMap)
	vdsname := strings.Split(c.name, "-")[0]
	log.Infof("vdsname is $$$$$$ %v", vdsname)
	c.datapathManager.OfSwitchMap[vdsname]["cls"] = sw

	c.clsSwitchStatusMutex.Lock()
	c.isClsSwitchConnected = true
	c.clsSwitchStatusMutex.Unlock()
}

func (c *ClsBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", c.name)

	c.ofSwitch = nil

	c.clsSwitchStatusMutex.Lock()
	c.isClsSwitchConnected = false
	c.clsSwitchStatusMutex.Unlock()
}

func (c *ClsBridge) IsSwitchConnected() bool {
	c.clsSwitchStatusMutex.Lock()
	defer c.clsSwitchStatusMutex.Unlock()

	return c.isClsSwitchConnected
}

func (c *ClsBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		c.clsSwitchStatusMutex.Lock()
		if c.isClsSwitchConnected {
			c.clsSwitchStatusMutex.Unlock()
			return
		}
		c.clsSwitchStatusMutex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", c.name)
}

func (c *ClsBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
}

func (c *ClsBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (c *ClsBridge) BridgeInit() error {
	c.clsBridgeLearningTable = c.ofSwitch.DefaultTable()
	c.clsBridgeForwardingTable, _ = c.ofSwitch.NewTable(CLSBRIDGE_FORWARDING_TABLE_ID)
	c.clsBridgeOutputTable, _ = c.ofSwitch.NewTable(CLSBRIDGE_OUTPUT_TABLE_ID)

	// clsBridge fromLocalLearningFlow
	fromLocalLearningFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: uint32(CLS_TO_POLICY_PORT),
	})

	fromLocalLearnAction := ofctrl.NewLearnAction(CLSBRIDGE_FORWARDING_TABLE_ID, NORMAL_MATCH_FLOW_PRIORITY, 10, 10, 0, 0, 0)
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
	err := fromLocalLearnAction.AddLearnedMatch(learnDstMatchField1, 16, learnSrcMatchField1, nil)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedMatch nxm_of_vlan_tci failure, error: %v", err)
	}
	err = fromLocalLearnAction.AddLearnedMatch(learnDstMatchField2, 48, learnSrcMatchField2, nil)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedMatch nxm_of_eth_dst failure, error: %v", err)
	}
	srcValue := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue, uint16(CLS_TO_POLICY_PORT))
	err = fromLocalLearnAction.AddLearnedLoadAction(&ofctrl.LearnField{Name: "nxm_nx_reg0", Start: 0}, 16, nil, srcValue)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedLoadAction: load:0xclsBridgeToPolicyBridgeOfPort->NXM_OF_REG0[] failure, error: %v", err)
	}

	fromLocalLearningFlow.Learn(fromLocalLearnAction)
	var forwardingTable, outputTable uint8 = CLSBRIDGE_FORWARDING_TABLE_ID, CLSBRIDGE_OUTPUT_TABLE_ID
	fromLocalLearningFlow.Resubmit(nil, &forwardingTable)
	fromLocalLearningFlow.Resubmit(nil, &outputTable)
	fromLocalLearningFlow.Next(ofctrl.NewEmptyElem())

	// clsBridge fromUplinkLearningFlow
	fromUplinkLearningFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority:  NORMAL_MATCH_FLOW_PRIORITY,
		InputPort: uint32(CLS_TO_UPLINK_PORT),
	})
	fromUplinkLearnAction := ofctrl.NewLearnAction(uint8(CLSBRIDGE_FORWARDING_TABLE_ID), NORMAL_MATCH_FLOW_PRIORITY, 10, 10, 0, 0, 0)
	learnDstMatchField3 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnSrcMatchField3 := &ofctrl.LearnField{
		Name:  "nxm_of_vlan_tci",
		Start: 0,
	}
	learnDstMatchField4 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_dst",
		Start: 0,
	}
	learnSrcMatchField4 := &ofctrl.LearnField{
		Name:  "nxm_of_eth_src",
		Start: 0,
	}
	err = fromUplinkLearnAction.AddLearnedMatch(learnDstMatchField3, 16, learnSrcMatchField3, nil)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedMatch nxm_of_vlan_tci failure, error: %v", err)
	}
	err = fromUplinkLearnAction.AddLearnedMatch(learnDstMatchField4, 48, learnSrcMatchField4, nil)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedMatch nxm_of_eth_dst failure, error: %v", err)
	}
	srcValue1 := make([]byte, 2)
	binary.BigEndian.PutUint16(srcValue1, uint16(CLS_TO_UPLINK_PORT))
	err = fromUplinkLearnAction.AddLearnedLoadAction(&ofctrl.LearnField{Name: "nxm_nx_reg0", Start: 0}, 16, nil, srcValue1)
	if err != nil {
		log.Fatalf("Failed to initialize learn action, AddLearnedLoadAction: load:ClsBridgeToUplinkBridgeOfPort->NXM_OF_REG0[] failure, error: %v", err)
	}
	fromUplinkLearningFlow.Learn(fromUplinkLearnAction)
	outputPort, _ := c.ofSwitch.OutputPort(uint32(CLS_TO_POLICY_PORT))
	fromUplinkLearningFlow.Next(outputPort)

	// demuxBridgeLearningTable learningTableDefaultFlow
	learningTableDefaultFlow, _ := c.clsBridgeLearningTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	learningTableDefaultFlow.Next(c.ofSwitch.DropAction())

	// demuxBridgeForwardingTable broadcast flow
	broadcastMac, _ := net.ParseMAC(BROADCAST_MAC_ADDRESS_MASK)
	fromLocalBroadcastMarkFlow, _ := c.clsBridgeForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority:  MID_MATCH_FLOW_PRIORITY,
		MacDa:     &broadcastMac,
		MacDaMask: &broadcastMac,
	})
	fromLocalBroadcastMarkFlow.LoadField("nxm_nx_reg0", 0, openflow13.NewNXRange(0, 15))
	fromLocalBroadcastMarkFlow.Next(ofctrl.NewEmptyElem())

	// demuxBridgeForwardingTable unlearnedFlow
	unlearnedFlow, _ := c.clsBridgeForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	unlearnedFlow.LoadField("nxm_nx_reg0", 0, openflow13.NewNXRange(0, 15))
	unlearnedFlow.Next(ofctrl.NewEmptyElem())

	// demuxBridgeOutputTable floodingOutputFlow
	floodingOutputFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: 0,
				Data:  0,
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})

	// outputAction1 := ofctrl.NewOutputAction("outputAction", uint32(CLS_TO_POLICY_PORT))
	outputAction1 := ofctrl.NewOutputAction("outputAction", uint32(openflow13.P_IN_PORT))
	outputAction2 := ofctrl.NewOutputAction("outputAction", uint32(CLS_TO_UPLINK_PORT))
	floodingOutputFlow.Output(outputAction1)
	floodingOutputFlow.Output(outputAction2)
	floodingOutputFlow.Next(ofctrl.NewEmptyElem())

	// clsBridge learnedLocalToLocalOutputFlow
	learnedLocalToLocalOutputFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: 0,
				Data:  uint32(CLS_TO_POLICY_PORT),
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ = c.ofSwitch.OutputPort(uint32(openflow13.P_IN_PORT))
	learnedLocalToLocalOutputFlow.Next(outputPort)

	// demuxBridgeOutputTable learnedLocalToRemoteOuputFlow
	learnedLocalToRemoteOuputFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: NORMAL_MATCH_FLOW_PRIORITY,
		Regs: []*ofctrl.NXRegister{
			{
				RegID: 0,
				Data:  uint32(CLS_TO_UPLINK_PORT),
				Range: openflow13.NewNXRange(0, 15),
			},
		},
	})
	outputPort, _ = c.ofSwitch.OutputPort(CLS_TO_UPLINK_PORT)
	learnedLocalToRemoteOuputFlow.Next(outputPort)

	// demuxBridgeOutputTable default flow
	outputTableDefaultFlow, _ := c.clsBridgeOutputTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	outputTableDefaultFlow.Next(c.ofSwitch.DropAction())

	return nil
}

func (c *ClsBridge) BridgeReset() error {
	return nil
}

func (c *ClsBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (c *ClsBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (p *ClsBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*ofctrl.Flow, error) {
	return nil, nil
}

func (c *ClsBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

func (c *ClsBridge) AddVNFInstance() error {
	return nil
}

func (c *ClsBridge) RemoveVNFInstance() error {
	return nil
}

func (c *ClsBridge) AddSFCRule() error {
	return nil
}

func (c *ClsBridge) RemoveSFCRule() error {
	return nil
}
