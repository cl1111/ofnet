package ofnet

import (
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"

	"github.com/contiv/ofnet/ofctrl"
	// "github.com/contiv/ofnet/ofctrl/cookie"
)

type UplinkBridge struct {
	name            string
	datapathManager *DatapathManager
	ofSwitch        *ofctrl.OFSwitch
	controller      *ofctrl.Controller

	normalForwardingTable *ofctrl.Table
	normalForwardingFlow  *ofctrl.Flow

	uplinkSwitchStatueMutex sync.RWMutex
	isUplinkSwitchConnected bool
}

func NewUplinkBridge(brName string, datapathManager *DatapathManager) *UplinkBridge {
	uplinkBridge := new(UplinkBridge)
	uplinkBridge.name = fmt.Sprintf("%s-uplink", brName)
	uplinkBridge.datapathManager = datapathManager
	return uplinkBridge
}

func (u *UplinkBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", u.name)

	log.Infof("cls switch connected : %v", u.datapathManager.OfSwitchMap)
	vdsname := strings.Split(u.name, "-")[0]
	u.datapathManager.OfSwitchMap[vdsname]["uplink"] = sw
	u.ofSwitch = sw

	u.uplinkSwitchStatueMutex.Lock()
	u.isUplinkSwitchConnected = true
	u.uplinkSwitchStatueMutex.Unlock()
}

func (u *UplinkBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", u.name)

	u.ofSwitch = nil

	u.uplinkSwitchStatueMutex.Lock()
	u.isUplinkSwitchConnected = false
	u.uplinkSwitchStatueMutex.Unlock()
}

func (u *UplinkBridge) IsSwitchConnected() bool {
	u.uplinkSwitchStatueMutex.Lock()
	defer u.uplinkSwitchStatueMutex.Unlock()

	return u.isUplinkSwitchConnected
}

func (u *UplinkBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		u.uplinkSwitchStatueMutex.Lock()
		if u.isUplinkSwitchConnected {
			u.uplinkSwitchStatueMutex.Unlock()
			return
		}
		u.uplinkSwitchStatueMutex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", u.name)
}

func (u *UplinkBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {
}

func (u *UplinkBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {
}

func (u *UplinkBridge) BridgeInit() error {
	sw := u.ofSwitch
	u.normalForwardingTable = sw.DefaultTable()

	defaultTableDefaultFlow, _ := u.normalForwardingTable.NewFlow(ofctrl.FlowMatch{
		Priority: DEFAULT_FLOW_PRIORITY,
	})
	if err := defaultTableDefaultFlow.Next(sw.NormalLookup()); err != nil {
		return fmt.Errorf("failed to install uplink default table default flow, error: %v", err)
	}
	return nil
}

func (u *UplinkBridge) BridgeReset() error {
	return nil
}

func (u *UplinkBridge) AddLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (u *UplinkBridge) RemoveLocalEndpoint(endpoint *Endpoint) error {
	return nil
}

func (p *UplinkBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8) (*ofctrl.Flow, error) {
	return nil, nil
}

func (u *UplinkBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

func (u *UplinkBridge) AddVNFInstance() error {
	return nil
}

func (u *UplinkBridge) RemoveVNFInstance() error {
	return nil
}

func (u *UplinkBridge) AddSFCRule() error {
	return nil
}

func (u *UplinkBridge) RemoveSFCRule() error {
	return nil
}
