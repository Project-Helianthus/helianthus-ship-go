package ship

import (
	"encoding/json"
	"errors"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

// Handshake Pin covers the states smePin...

func (c *ShipConnection) handshakePin_Init() {
	c.setState(model.SmePinStateCheckInit, nil)

	pinState := model.ConnectionPinState{
		ConnectionPinState: model.ConnectionPinStateType{
			PinState: model.PinStateTypeNone,
		},
	}

	if err := c.sendShipModel(model.MsgTypeControl, pinState); err != nil {
		c.endHandshakeWithError(err)
		return
	}

	c.setState(model.SmePinStateAskInit, nil)
}

func (c *ShipConnection) handshakePin_smePinStateCheckListen(message []byte) {
	_, data := c.parseMessage(message, true)
	var envelope struct {
		ConnectionPinState *model.ConnectionPinStateType `json:"connectionPinState"`
		ConnectionPinError *model.ConnectionPinErrorType `json:"connectionPinError"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		c.endHandshakeWithError(api.ErrPINProtocol)
		return
	}
	if envelope.ConnectionPinError != nil {
		if envelope.ConnectionPinError.Error == model.ConnectionPinErrorErrorTypeWrongPIN && c.wasPINInputSent() {
			c.endHandshakeWithError(api.ErrPINRejected)
			return
		}
		c.endHandshakeWithError(api.ErrPINProtocol)
		return
	}
	if envelope.ConnectionPinState == nil {
		c.endHandshakeWithError(api.ErrPINProtocol)
		return
	}
	c.processRemotePINState(*envelope.ConnectionPinState)
}

func (c *ShipConnection) processRemotePINState(pinState model.ConnectionPinStateType) {
	switch pinState.PinState {
	case model.PinStateTypeNone, model.PinStateTypePinOk:
		if pinState.InputPermission != nil {
			c.endHandshakeWithError(api.ErrPINProtocol)
			return
		}
		c.discardTransientPIN()
		c.setAndHandleState(model.SmePinStateCheckOk)
	case model.PinStateTypeRequired, model.PinStateTypeOptional:
		if pinState.InputPermission == nil {
			c.endHandshakeWithError(api.ErrPINProtocol)
			return
		}
		switch *pinState.InputPermission {
		case model.PinInputPermissionTypeBusy:
			c.setState(model.SmePinStateAskProcess, nil)
		case model.PinInputPermissionTypeOk:
			c.processRemotePINRequest(pinState.PinState)
		default:
			c.endHandshakeWithError(api.ErrPINProtocol)
		}
	default:
		c.endHandshakeWithError(api.ErrPINProtocol)
	}
}

func (c *ShipConnection) processRemotePINRequest(requirement model.PinStateType) {
	if c.wasPINInputSent() {
		c.setState(model.SmePinStateAskProcess, nil)
		return
	}
	// Move to the SHIP-defined PIN response window before invoking the provider:
	// an interactive provider may legitimately take longer than the generic CMI
	// timeout, and a concurrent close must prevent any later sensitive write.
	if !c.setState(model.SmePinStateAskProcess, nil) {
		return
	}

	provided, providerErr := c.withTransientPIN(func(pin []byte) error {
		if !c.beginPINInput() {
			return api.ErrPINUnavailable
		}
		if err := c.sendTransientPIN(pin); err != nil {
			c.rollbackPINInput()
			return err
		}
		return nil
	})
	if providerErr != nil {
		if errors.Is(providerErr, api.ErrPINInvalid) {
			c.endHandshakeWithError(api.ErrPINInvalid)
		} else {
			c.endHandshakeWithError(api.ErrPINUnavailable)
		}
		return
	}
	if !provided {
		if requirement == model.PinStateTypeOptional {
			c.setAndHandleState(model.SmePinStateAskRestricted)
			return
		}
		c.endHandshakeWithError(api.ErrPINUnavailable)
		return
	}
	if c.getState() == model.SmePinStateAskProcess {
		c.setHandshakeTimer(timeoutTimerTypeWaitForReady, pinResponseTimeout)
	}
}

func (c *ShipConnection) withTransientPIN(consume func([]byte) error) (bool, error) {
	provider, ok := c.infoProvider.(api.TransientPINProvider)
	if !ok || provider == nil {
		return false, nil
	}
	consumed := false
	provided, err := provider.WithTransientPIN(c.remoteSKI, func(pin []byte) error {
		if consumed {
			return api.ErrPINInvalid
		}
		consumed = true
		return consume(pin)
	})
	if err != nil {
		if errors.Is(err, api.ErrPINInvalid) {
			return false, api.ErrPINInvalid
		}
		return false, api.ErrPINUnavailable
	}
	if provided != consumed {
		return false, api.ErrPINUnavailable
	}
	return provided, nil
}

func (c *ShipConnection) discardTransientPIN() {
	if discarder, ok := c.infoProvider.(api.TransientPINDiscarder); ok && discarder != nil {
		discarder.DiscardTransientPIN(c.remoteSKI)
	}
}

func (c *ShipConnection) sendTransientPIN(pin []byte) error {
	if !validTransientPIN(pin) {
		return api.ErrPINInvalid
	}
	writer, ok := c.dataWriter.(api.SensitiveWebsocketDataWriterInterface)
	if !ok || writer == nil {
		return api.ErrPINUnavailable
	}

	const prefix = `{"connectionPinInput":[{"pin":"`
	const suffix = `"}]}`
	message := make([]byte, 0, 1+len(prefix)+len(pin)+len(suffix))
	message = append(message, model.MsgTypeControl)
	message = append(message, prefix...)
	message = append(message, pin...)
	message = append(message, suffix...)
	defer clear(message)
	c.shipWriteMux.Lock()
	defer c.shipWriteMux.Unlock()
	if c.shutdownRequested() {
		return api.ErrPINUnavailable
	}
	if err := writer.WriteSensitiveMessageToWebsocketConnection(message); err != nil {
		return api.ErrPINUnavailable
	}
	return nil
}

func validTransientPIN(pin []byte) bool {
	if len(pin) < 8 || len(pin) > 16 {
		return false
	}
	for _, value := range pin {
		if !((value >= '0' && value <= '9') ||
			(value >= 'a' && value <= 'f') ||
			(value >= 'A' && value <= 'F')) {
			return false
		}
	}
	return true
}
