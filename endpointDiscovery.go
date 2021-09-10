package ofnet

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/contiv/libovsdb"
)

const (
	LocalEndpointIdentity = "attached-mac"
	UplinkPortIdentity    = "uplink-port"
)

var (
	uplinkUpdates       libovsdb.RowUpdate
	isUplinkPortUpdated bool
)

type EventHandler interface {
	AddLocalEndpoint(endpoint Endpoint)
	RemoveLocalEndPoint(endpoint Endpoint)
	UpdateUplinkActiveSlave(ofPort uint32)
	AddUplink(port *PortInfo)
	DeleteUplink(portName string)
}

// type ovsdbEventHandlerFunc func(eventParams interface{})
type OvsdbEventHandlerFuncs struct {
	LocalEndpointAddFunc        func(endpoint Endpoint)
	LocalEndpointDeleteFunc     func(endpoint Endpoint)
	UplinkActiveSlaveUpdateFunc func(portName string, updates PortUpdates)
	UplinkAddFunc               func(port *PortInfo)
	UplinkDelFunc               func(portName string)
}

func (o *ovsdbEventHandler) RegisterOvsdbEventCallbackHandlerFunc(eventHandler EventHandler) {
	o.eventHandler = eventHandler
}

func (o OvsdbEventHandlerFuncs) AddLocalEndpoint(endpoint Endpoint) {
	if o.LocalEndpointAddFunc != nil {
		o.LocalEndpointAddFunc(endpoint)
	}
}

func (o OvsdbEventHandlerFuncs) RemoveLocalEndPoint(endpoint Endpoint) {
	if o.LocalEndpointDeleteFunc != nil {
		o.LocalEndpointDeleteFunc(endpoint)
	}
}

func (o OvsdbEventHandlerFuncs) UpdateUplinkActiveSlave(ofPort uint32) {
	if o.UplinkActiveSlaveUpdateFunc != nil {
		portUpdate := PortUpdates{
			// Updates: []PortUpdate{{
			// 	UpdateType: BondActiveSlaveSwitch,
			// 	UpdateInfo: LinkUpdateInfo{
			// 		ActiveSlaveOfPort: ofPort,
			// 	},
			// }},
		}
		o.UplinkActiveSlaveUpdateFunc("", portUpdate)
	}

}

func (o OvsdbEventHandlerFuncs) AddUplink(port *PortInfo) {
	if o.UplinkAddFunc != nil {
		o.UplinkAddFunc(port)
	}
}

func (o OvsdbEventHandlerFuncs) DeleteUplink(portName string) {
	if o.UplinkDelFunc != nil {
		o.UplinkDelFunc(portName)
	}
}

type ovsdbEventHandler struct {
	cacheLock   sync.RWMutex
	ovsdbCache  map[string]map[string]libovsdb.Row
	ovsdbClient *libovsdb.OvsdbClient

	eventHandler                   EventHandler
	localEndpointHardWareAddrCache sets.String
	updatingUplinkMutex            sync.RWMutex
	inUpdatingUplinkPortMap        map[string]libovsdb.RowUpdate
	isUpdatingUplinkActive         bool
}

func NewOvsdbEventHandler(ovsdbClient *libovsdb.OvsdbClient) *ovsdbEventHandler {
	ovsdbCacheMap := make(map[string]map[string]libovsdb.Row)
	ovsdbEventHandler := &ovsdbEventHandler{
		ovsdbCache:              ovsdbCacheMap,
		ovsdbClient:             ovsdbClient,
		inUpdatingUplinkPortMap: make(map[string]libovsdb.RowUpdate),
	}

	ovsdbEventHandler.localEndpointHardWareAddrCache = sets.NewString()
	ovsdbEventHandler.isUpdatingUplinkActive = false

	return ovsdbEventHandler
}

func (o *ovsdbEventHandler) StartOvsdbEventHandler() error {
	o.ovsdbClient.Register(o)

	selectAll := libovsdb.MonitorSelect{
		Initial: true,
		Insert:  true,
		Delete:  true,
		Modify:  true,
	}
	requests := map[string]libovsdb.MonitorRequest{
		"Port":         {Select: selectAll, Columns: []string{"name", "interfaces", "external_ids", "bond_active_slave", "bond_mode", "vlan_mode", "tag", "trunks"}},
		"Interface":    {Select: selectAll, Columns: []string{"name", "mac_in_use", "ofport", "type", "external_ids"}},
		"Bridge":       {Select: selectAll, Columns: []string{"name", "ports"}},
		"Open_vSwitch": {Select: selectAll, Columns: []string{"ovs_version"}},
	}

	initial, err := o.ovsdbClient.Monitor("Open_vSwitch", nil, requests)
	if err != nil {
		return fmt.Errorf("monitor ovsdb %s: %s", "Open_vSwitch", err)
	}

	o.Update(nil, *initial)

	return nil
}

func (o *ovsdbEventHandler) interfaceToEndpoint(ofport uint32, interfaceName, macAddrStr string) *Endpoint {
	// NOTE should use interface uuid to caculate endpoint info
	var bridgeName string
	var portUUID string
	var vlanID uint16
	for uuid, port := range o.ovsdbCache["Port"] {
		if port.Fields["name"].(string) == interfaceName {
			portUUID = uuid
			tag, ok := port.Fields["tag"].(float64)
			if !ok {
				break
			}
			vlanID = uint16(tag)
			break
		}
	}

	for _, bridge := range o.ovsdbCache["Bridge"] {
		portUUIDs := listUUID(bridge.Fields["ports"])
		for _, uuid := range portUUIDs {
			if uuid.GoUuid == portUUID {
				bridgeName = bridge.Fields["name"].(string)
				break
			}
		}
	}

	return &Endpoint{
		MacAddrStr: macAddrStr,
		PortNo:     ofport,
		BridgeName: bridgeName,
		VlanID:     vlanID,
	}
}

func (o *ovsdbEventHandler) filterEndpointAdded(rowupdate libovsdb.RowUpdate) *Endpoint {
	if rowupdate.New.Fields["external_ids"] == nil {
		return nil
	}

	newExternalIds := rowupdate.New.Fields["external_ids"].(libovsdb.OvsMap).GoMap
	if _, ok := newExternalIds["attached-mac"]; ok {
		if o.localEndpointHardWareAddrCache.Has(newExternalIds["attached-mac"].(string)) {
			return nil
		}
		o.localEndpointHardWareAddrCache.Insert(newExternalIds["attached-mac"].(string))

		ofPort, ok := rowupdate.New.Fields["ofport"].(float64)
		if ok && ofPort <= 0 {
			log.Errorf("Parsing endpoint ofport error: %v", ofPort)
			return nil
		}
		ofport := uint32(ofPort)

		// macAddr, err := net.ParseMAC(newExternalIds["attached-mac"].(string))
		// if err != nil {
		// 	log.Errorf("Parsing endpoint macAddr error: %v", macAddr)
		// 	return nil
		// }
		// NOTE get bridge of this interface attached to
		endpoint := o.interfaceToEndpoint(ofport, rowupdate.New.Fields["name"].(string), newExternalIds["attached-mac"].(string))

		return endpoint

		// return &Endpoint{
		// 	MacAddrStr: newExternalIds["attached-mac"].(string),
		// 	PortNo:     ofport,
		// 	BridgeName: bridgeName,
		// }
	}

	return nil
}

func (o *ovsdbEventHandler) filterEndpoingDeleted(rowupdate libovsdb.RowUpdate) *Endpoint {
	if rowupdate.Old.Fields["external_ids"] == nil {
		return nil
	}

	oldExternalIds := rowupdate.Old.Fields["external_ids"].(libovsdb.OvsMap).GoMap
	if _, ok := oldExternalIds["attached-mac"]; ok {
		if o.localEndpointHardWareAddrCache.Has(oldExternalIds["attached-mac"].(string)) {
			o.localEndpointHardWareAddrCache.Delete(oldExternalIds["attached-mac"].(string))

			ofPort, ok := rowupdate.Old.Fields["ofport"].(float64)
			if ok && ofPort <= 0 {
				log.Errorf("Parsing endpoint ofport error: %v", ofPort)
				return nil
			}

			ofport := uint32(ofPort)

			// bridgeName := o.interfaceToBridge(rowupdate.Old.Fields["name"].(string))
			endpoint := o.interfaceToEndpoint(ofport, rowupdate.Old.Fields["name"].(string), oldExternalIds["attached-mac"].(string))
			return endpoint
		}
	}

	return nil
}

func (o *ovsdbEventHandler) filterUplinkDeleted(rowupdate libovsdb.RowUpdate) *string {
	if rowupdate.Old.Fields["external_ids"] == nil {
		return nil
	}

	oldExternalIds := rowupdate.Old.Fields["external_ids"].(libovsdb.OvsMap).GoMap
	if _, ok := oldExternalIds[UplinkPortIdentity]; ok {
		uplinkPortName := rowupdate.Old.Fields["name"].(string)

		return &uplinkPortName
	}

	return nil
}

func (o *ovsdbEventHandler) filterUplinkPort(rowupdate libovsdb.RowUpdate) bool {
	if rowupdate.New.Fields["external_ids"] == nil {
		return false
	}

	newExternalIds := rowupdate.New.Fields["external_ids"].(libovsdb.OvsMap).GoMap
	if _, ok := newExternalIds[UplinkPortIdentity]; !ok {
		return false
	}

	return true
}

func (o *ovsdbEventHandler) filterBondModeUpdate(rowupdate libovsdb.RowUpdate) bool {
	if rowupdate.New.Fields["bond_mode"] != nil && rowupdate.Old.Fields["bond_mode"] != nil &&
		!reflect.DeepEqual(rowupdate.New.Fields["bond_mode"], rowupdate.Old.Fields["bond_mode"]) {

		// fmt.Println("########### new bond mode:", rowupdate.New.Fields["bond_mode"], "old bond mode:", rowupdate.Old.Fields["bond_mode"])
		return true
	}

	return false
}

func (o *ovsdbEventHandler) filterBondActiveSlaveUpdate(rowupdate libovsdb.RowUpdate) bool {
	if rowupdate.New.Fields["bond_active_slave"] != nil && rowupdate.Old.Fields["bond_active_slave"] != nil &&
		!reflect.DeepEqual(rowupdate.New.Fields["bond_active_slave"], rowupdate.Old.Fields["bond_active_slave"]) {

		// fmt.Println("########### bond active slave switch")
		return true
	}

	return false
}

func (o *ovsdbEventHandler) filterUplinkPortAlreadyAdded(rowupdate libovsdb.RowUpdate) bool {
	if rowupdate.Old.Fields["external_ids"] != nil {
		oldExternalIds := rowupdate.Old.Fields["external_ids"].(libovsdb.OvsMap).GoMap
		if _, ok := oldExternalIds[UplinkPortIdentity]; ok {
			// UplinkPortIdentity already exists
			return true
		}
	}

	return false
}

func (o *ovsdbEventHandler) filterCurrentBondActiveSlave(rowupdate libovsdb.RowUpdate) *uint32 {
	var activeInterfaceOfPort uint32

	curActiveSlaveMacAddr, _ := rowupdate.New.Fields["bond_active_slave"].(string)
	if curActiveSlaveMacAddr == "" {
		return nil
	}

	bondInterfaceUUIds := listUUID(rowupdate.New.Fields["interfaces"])
	for _, interfaceUUId := range bondInterfaceUUIds {
		ovsInterface, ok := o.ovsdbCache["Interface"][interfaceUUId.GoUuid]
		if !ok {
			log.Infof("Failed to get bonded uplink port interface: %+v", interfaceUUId)
			continue
		}

		interfaceMac, _ := ovsInterface.Fields["mac_in_use"].(string)
		if interfaceMac == curActiveSlaveMacAddr {
			ofPort, ok := ovsInterface.Fields["ofport"].(float64)
			if ok && ofPort > 0 {
				activeInterfaceOfPort = uint32(ofPort)
			}

			// fmt.Println("############# processing bond active slave update", activeInterfaceOfPort)
			return &activeInterfaceOfPort
		}
	}

	return nil
}

func (o *ovsdbEventHandler) buildPortInfo(rowupdate libovsdb.RowUpdate) *PortInfo {
	var portInfo *PortInfo
	var mbrLinkInfo []*LinkInfo
	var portType string = "individual"
	uplinkPortName := rowupdate.New.Fields["name"].(string)

	uplinkInterfaceUUIds := listUUID(rowupdate.New.Fields["interfaces"])
	if len(uplinkInterfaceUUIds) != 1 {
		portType = "bond"
	}

	for _, interfaceUUId := range uplinkInterfaceUUIds {
		var interfaceOfPort uint32
		uplinkInterface, ok := o.ovsdbCache["Interface"][interfaceUUId.GoUuid]
		if !ok {
			fmt.Println("Failed to get uplinkInterface", uplinkInterface)
			return nil
		}

		interfaceName, _ := uplinkInterface.Fields["name"].(string)
		ofport, ok := uplinkInterface.Fields["ofport"].(float64)
		if ok && ofport > 0 {
			interfaceOfPort = uint32(ofport)
		}

		if ofport <= 0 {
			return nil
		}

		mbrLinkInfo = append(mbrLinkInfo, &LinkInfo{
			Name:       interfaceName,
			OfPort:     interfaceOfPort,
			LinkStatus: 0,
			Port:       portInfo,
		})
	}

	portInfo = &PortInfo{
		Name:       uplinkPortName,
		Type:       portType,
		LinkStatus: 0,
		MbrLinks:   mbrLinkInfo,
	}

	return portInfo
}

func (o *ovsdbEventHandler) processInterfaceUpdate(rowupdate libovsdb.RowUpdate) {
	// fmt.Println("interface update\n: rowNew", rowupdate.New)
	// fmt.Println("****** rowOld", rowupdate.Old)

	addedEndpoints := o.filterEndpointAdded(rowupdate)
	if addedEndpoints != nil {
		go o.eventHandler.AddLocalEndpoint(*addedEndpoints)
	}
}

// NOTE, if callback excute failed, but ovsdbCache already updated, we can't properly delete endpoint
func (o *ovsdbEventHandler) processInterfaceDelete(rowupdate libovsdb.RowUpdate) {
	// fmt.Println("interface update\n: rowNew", rowupdate.New)
	// fmt.Println("****** rowOld", rowupdate.Old)

	deletedEndpoints := o.filterEndpoingDeleted(rowupdate)
	if deletedEndpoints != nil {
		go o.eventHandler.RemoveLocalEndPoint(*deletedEndpoints)
	}
}

// Asynchronize implement
func (o *ovsdbEventHandler) processPortUpdate(rowupdate libovsdb.RowUpdate) {
	// fmt.Println("port update\n: rowNew", rowupdate.New)
	// fmt.Println("****** rowOld", rowupdate.Old)

	isUplinkPort := o.filterUplinkPort(rowupdate)
	if !isUplinkPort {
		return
	}

	isBondModeUpdate := o.filterBondModeUpdate(rowupdate)
	if isBondModeUpdate {
		return
	}

	isBondActiveSlaveUpdate := o.filterBondActiveSlaveUpdate(rowupdate)
	if isBondActiveSlaveUpdate {
		curActiveSlaveInterfaceOfPort := o.filterCurrentBondActiveSlave(rowupdate)
		if curActiveSlaveInterfaceOfPort != nil {
			// fmt.Println("########### uplink active slave update")
			o.processBondActiveSlaveSwitch(*curActiveSlaveInterfaceOfPort)
		}
		return
	}

	if o.filterUplinkPortAlreadyAdded(rowupdate) {
		// fmt.Println("########### uplink already added")
		return
	}

	addedUplinkPortName, _ := rowupdate.New.Fields["name"].(string)
	addedUplinkPort := o.buildPortInfo(rowupdate)

	if addedUplinkPort != nil {
		// fmt.Println("########### uplink add", addedUplinkPort.Name)
		go o.eventHandler.AddUplink(addedUplinkPort)
		if _, ok := o.inUpdatingUplinkPortMap[addedUplinkPortName]; ok {
			o.updatingUplinkMutex.Lock()
			delete(o.inUpdatingUplinkPortMap, addedUplinkPortName)
			o.updatingUplinkMutex.Unlock()
		}
	} else {
		// fmt.Println("########### inUpdating uplink add event", addedUplinkPortName)
		o.updatingUplinkMutex.Lock()
		defer o.updatingUplinkMutex.Unlock()

		o.inUpdatingUplinkPortMap[addedUplinkPortName] = rowupdate

		if !o.isUpdatingUplinkActive {
			go o.processInUpdatingUplinkAdd()
			o.isUpdatingUplinkActive = true
		}
	}
}

func (o *ovsdbEventHandler) processInUpdatingUplinkAdd() {
	// fmt.Println("########### process inUpdating uplink add event", o.inUpdatingUplinkPortMap)
	for {
		o.updatingUplinkMutex.Lock()

		done := true
		for portname, row := range o.inUpdatingUplinkPortMap {
			// cacheLock
			o.cacheLock.Lock()
			addedUplinkPort := o.buildPortInfo(row)
			o.cacheLock.Unlock()

			if addedUplinkPort != nil {
				// fmt.Println("########### complete inUpdating uplink add event", addedUplinkPort)
				go o.eventHandler.AddUplink(addedUplinkPort)
				delete(o.inUpdatingUplinkPortMap, portname)

				continue
			}
			done = false
		}

		if done {
			o.isUpdatingUplinkActive = false
			o.updatingUplinkMutex.Unlock()

			return
		}

		o.updatingUplinkMutex.Unlock()
		time.Sleep(time.Millisecond * 300)
	}
}

// Asynchronize implement end

// synchronize implement
// func (o *ovsdbEventHandler) processUplinkAdd(rowupdate libovsdb.RowUpdate) {
// 	fmt.Println("rowNew", rowupdate.New)
// 	fmt.Println("****** newExternalIds", rowupdate.New.Fields["external_ids"])

// 	fmt.Println("****** rowOld", rowupdate.Old)
// 	fmt.Println("****** oldExternalIds", rowupdate.Old.Fields["external_ids"])

// 	isUplinkPort := o.filterUplinkPort(rowupdate)
// 	if !isUplinkPort {
// 		return
// 	}

// 	isBondModeUpdate := o.filterBondModeUpdate(rowupdate)
// 	if isBondModeUpdate {
// 		return
// 	}

// 	isBondActiveSlaveUpdate := o.filterBondActiveSlaveUpdate(rowupdate)
// 	if isBondActiveSlaveUpdate {
//         curActiveSlaveInterfaceOfPort := o.filterCurrentBondActiveSlave(rowupdate)
//         if curActiveSlaveInterfaceOfPort != nil {
//             o.processBondActiveSlaveSwitch(*curActiveSlaveInterfaceOfPort)
//         }
// 		return
// 	}

// 	addedUplinkPortName, _ := rowupdate.New.Fields["name"].(string)
// 	addedUplinkPort := o.filterUplinkAdded(rowupdate)

// 	if addedUplinkPort != nil {
// 		fmt.Println("########### uplink add", addedUplinkPort.Name)
// 		go o.eventHandler.AddUplink(addedUplinkPort)
// 		// o.updatingUplinkMutex.Lock()
// 		if _, ok := o.inUpdatingUplinkPortMap[addedUplinkPortName]; ok {
// 			delete(o.inUpdatingUplinkPortMap, addedUplinkPortName)
// 		}
// 		// o.updatingUplinkMutex.Unlock()
// 	} else {
//         fmt.Println("########### add inUpdating uplink port", rowupdate)
// 		o.inUpdatingUplinkPortMap[addedUplinkPortName] = rowupdate
// 	}
// }
// synchronize implement end

func (o *ovsdbEventHandler) processBondActiveSlaveSwitch(curActiveSlaveInterfaceOfPort uint32) {
	// fmt.Printf("Switch bond active slave to: %+v\n", curActiveSlaveInterfaceOfPort)
	go o.eventHandler.UpdateUplinkActiveSlave(curActiveSlaveInterfaceOfPort)
}

func (o *ovsdbEventHandler) processPortDelete(rowupdate libovsdb.RowUpdate) {
	// fmt.Println("Port delete\n: ******* rowNew", rowupdate.New)
	// fmt.Println("****** rowOld", rowupdate.Old)

	deletedPortName := o.filterUplinkDeleted(rowupdate)
	if deletedPortName != nil {
		log.Infof("deletedPortName: %+v", deletedPortName)
		go o.eventHandler.DeleteUplink(*deletedPortName)
	}
}

func listUUID(uuidList interface{}) []libovsdb.UUID {
	var idList []libovsdb.UUID

	switch uuidList.(type) {
	case libovsdb.UUID:
		return []libovsdb.UUID{uuidList.(libovsdb.UUID)}
	case libovsdb.OvsSet:
		uuidSet := uuidList.(libovsdb.OvsSet).GoSet
		for item := range uuidSet {
			idList = append(idList, listUUID(uuidSet[item])...)
		}
	}

	return idList
}

func (o *ovsdbEventHandler) Update(context interface{}, tableUpdates libovsdb.TableUpdates) {
	o.cacheLock.Lock()
	defer o.cacheLock.Unlock()

	for table, tableUpdate := range tableUpdates.Updates {
		if _, ok := o.ovsdbCache[table]; !ok {
			o.ovsdbCache[table] = make(map[string]libovsdb.Row)
		}
		for uuid, row := range tableUpdate.Rows {
			empty := libovsdb.Row{}
			if !reflect.DeepEqual(row.New, empty) {
				switch table {
				case "Interface":
					o.processInterfaceUpdate(row)
					// fmt.Println("&&&&&&&&&&&&&& interface add event", row.New.Fields)
				case "Port":
					// fmt.Println("&&&&&&&&&&&&&& port add event", row.New.Fields)
					o.processPortUpdate(row)
				}

				o.ovsdbCache[table][uuid] = row.New
			} else {
				switch table {
				case "Interface":
					// fmt.Println("&&&&&&&&&&&&&& interface delete event", row.Old.Fields)
					o.processInterfaceDelete(row)
				case "Port":
					o.processPortDelete(row)
				}

				delete(o.ovsdbCache[table], uuid)
			}
		}
	}

	// synchronize implement
	// for portname, row := range o.inUpdatingUplinkPortMap {
	// 	addedUplinkPort := o.buildPortInfo(row)
	// 	if addedUplinkPort != nil {
	// 		fmt.Println("########### complete inUpdating uplink add event", addedUplinkPort)
	// 		go o.eventHandler.AddUplink(addedUplinkPort)
	// 		delete(o.inUpdatingUplinkPortMap, portname)
	// 	}
	// }
	// end synchronize implement

}

func (o *ovsdbEventHandler) Locked(context []interface{}) {

}

func (o *ovsdbEventHandler) Stolen(context []interface{}) {
}

func (o *ovsdbEventHandler) Echo(context []interface{}) {
}
