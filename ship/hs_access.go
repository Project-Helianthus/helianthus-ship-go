package ship

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

// Handshake Access covers the states smeAccess...

func (c *ShipConnection) handshakeAccessMethods_Init() {
	// Access Methods
	accessMethodsRequest := model.AccessMethodsRequest{
		AccessMethodsRequest: model.AccessMethodsRequestType{},
	}

	if err := c.sendShipModel(model.MsgTypeControl, accessMethodsRequest); err != nil {
		c.endHandshakeWithError(err)
		return
	}

	c.setHandshakeTimer(timeoutTimerTypeWaitForReady, cmiTimeout)
	c.setState(model.SmeAccessMethodsRequest, nil)
}

func (c *ShipConnection) handshakeAccessMethods_Request(message []byte) {
	_, data := c.parseMessage(message, true)

	dataString := string(data)

	if strings.Contains(dataString, "\"accessMethodsRequest\":{") {
		methodsId := c.localShipID

		accessMethods := model.AccessMethods{
			AccessMethods: model.AccessMethodsType{
				Id: &methodsId,
			},
		}
		if err := c.sendShipModel(model.MsgTypeControl, accessMethods); err != nil {
			c.endHandshakeWithError(err)
		}
		return
	} else if strings.Contains(dataString, "\"accessMethods\":{") {
		// compare SHIP ID to stored value on pairing. SKI + SHIP ID should be verified on connection
		// otherwise close connection with error "close 4450: SHIP id mismatch"

		var accessMethods model.AccessMethods
		if err := json.Unmarshal([]byte(data), &accessMethods); err != nil {
			c.endHandshakeWithError(err)
			return
		}

		if accessMethods.AccessMethods.Id == nil {
			c.endHandshakeWithError(errors.New("Access methods response does not contain SHIP ID"))
			return
		}

		// if the ID string is empty, then we don't know it yet and can't be verified
		if len(c.remoteShipID) > 0 && c.remoteShipID != *accessMethods.AccessMethods.Id {
			c.endHandshakeWithError(errors.New("SHIP id mismatch"))
			return
		}

		// Save the SHIP ID. The approved state is published only after the
		// identity callback returns; synchronous trust approval is latched until
		// both callbacks have completed.
		shipIDWasUnknown := len(c.remoteShipID) == 0
		if len(c.remoteShipID) == 0 {
			c.remoteShipID = *accessMethods.AccessMethods.Id
		}

		c.stopHandshakeTimer()
		shouldReportShipID := shipIDWasUnknown || c.pairingApprovalPending()
		if c.testHooks != nil && c.testHooks.beforePairingCommit != nil {
			c.testHooks.beforePairingCommit()
		}
		if !c.beginPairingCommit() {
			return
		}
		if shouldReportShipID {
			if !c.reportServiceShipID() {
				return
			}
		}
		if !c.publishPairingApproved() {
			return
		}
		if c.completePairingCommitCallback() {
			c.approveHandshake()
		}
		c.approveHandshake()
		return
	} else {
		c.endHandshakeWithError(fmt.Errorf("access methods: invalid response: %s", dataString))
		return
	}
}
