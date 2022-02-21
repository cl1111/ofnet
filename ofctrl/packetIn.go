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
// "net"
// "strings"
// "sync"
// "time"

// "github.com/contiv/libOpenflow/common"
// "github.com/contiv/libOpenflow/openflow13"
// "github.com/contiv/libOpenflow/protocol"
// "github.com/contiv/libOpenflow/util"

// log "github.com/Sirupsen/logrus"
)

const (
// PacketIn source definition

)

// packetIn handler interface for support parsing several type of packetin message like active probe traffic, network policy log, connection reject etc.
type PacketInHandler interface {
	HandlePacketIn()
}
