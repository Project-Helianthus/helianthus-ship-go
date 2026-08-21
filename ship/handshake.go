package ship

import (
	"errors"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

// handle incoming SHIP messages and coordinate Handshake States
func (c *ShipConnection) handleShipMessage(timeout bool, message []byte) {
	if len(message) > 2 {
		var closeMsg model.ConnectionClose
		err := c.processShipJsonMessage(message, &closeMsg)
		if err == nil && closeMsg.ConnectionClose.Phase != "" {
			switch closeMsg.ConnectionClose.Phase {
			case model.ConnectionClosePhaseTypeAnnounce:
				// SHIP 13.4.7: Connection Termination Confirm
				closeMessage := model.ConnectionClose{
					ConnectionClose: model.ConnectionCloseType{
						Phase: model.ConnectionClosePhaseTypeConfirm,
					},
				}

				_ = c.sendShipModel(model.MsgTypeEnd, closeMessage)
				c.CloseConnection(false, 4001, "remote close announce")
			case model.ConnectionClosePhaseTypeConfirm:
				// we got a confirmation so close this connection
				c.CloseConnection(false, 4001, "remote close confirm")
			}

			return
		}
	}

	c.handleState(timeout, message)
}

// set a new handshake state and handle timers if needed
func (c *ShipConnection) setState(newState model.ShipMessageExchangeState, err error) bool {
	c.pairingApprovalMux.Lock()
	if c.pairingClosing || c.pairingTerminal {
		c.pairingApprovalMux.Unlock()
		return false
	}
	c.mux.Lock()

	oldState := c.smeState

	c.smeState = newState
	logging.Log().Trace(c.RemoteSKI(), "SHIP state changed to:", newState)

	switch newState {
	case model.SmeHelloStateReadyInit:
		c.setHandshakeTimer(timeoutTimerTypeWaitForReady, tHelloInit)
	case model.SmeHelloStatePendingInit:
		c.setHandshakeTimer(timeoutTimerTypeWaitForReady, tHelloInit)
	case model.SmeHelloStateOk:
		c.stopHandshakeTimer()
	case model.SmeHelloStateAbort, model.SmeHelloStateAbortDone, model.SmeHelloStateRemoteAbortDone, model.SmeHelloStateRejected:
		c.stopHandshakeTimer()
	case model.SmeProtHStateClientListenChoice:
		c.setHandshakeTimer(timeoutTimerTypeWaitForReady, cmiTimeout)
	case model.SmeProtHStateClientOk:
		c.stopHandshakeTimer()
	case model.SmePinStateAskInit:
		c.setHandshakeTimer(timeoutTimerTypeWaitForReady, cmiTimeout)
	case model.SmePinStateAskProcess:
		if c.pinInputSent {
			c.setHandshakeTimer(timeoutTimerTypeWaitForReady, pinResponseTimeout)
		} else if oldState != model.SmePinStateAskProcess {
			c.setHandshakeTimer(timeoutTimerTypeWaitForReady, pinBusyTimeout)
		}
	case model.SmePinStateCheckOk, model.SmePinStateAskRestricted, model.SmePinStateAskOk:
		c.stopHandshakeTimer()
	}

	c.smeError = nil
	if oldState != newState {
		c.smeError = err
		state := model.ShipState{
			State: newState,
			Error: err,
			PIN:   c.pinHandshakeDetail.Clone(),
		}
		_, shouldDrain := c.enqueuePairingEffect(func() {
			c.reportShipHandshakeStateUpdate(state)
		})
		c.mux.Unlock()
		c.pairingApprovalMux.Unlock()
		if shouldDrain {
			c.drainPairingEffects()
		}
		return true
	}
	c.mux.Unlock()
	c.pairingApprovalMux.Unlock()
	return true
}

func (c *ShipConnection) getState() model.ShipMessageExchangeState {
	c.mux.Lock()
	defer c.mux.Unlock()

	return c.smeState
}

// handle handshake state transitions
func (c *ShipConnection) handleState(timeout bool, message []byte) {
	if !c.pairingEffectAllowed() {
		return
	}
	switch c.getState() {
	case model.SmeStateError:
		logging.Log().Debug(c.RemoteSKI(), "connection is in error state")
		return

	// cmiStateInit
	case model.CmiStateInitStart:
		// triggered without a message received
		c.handshakeInit_cmiStateInitStart()

	case model.CmiStateClientWait:
		if timeout {
			c.endHandshakeWithError(errors.New("ship client handshake timeout"))
			return
		}

		c.handshakeInit_cmiStateClientWait(message)

	case model.CmiStateServerWait:
		if timeout {
			c.endHandshakeWithError(errors.New("ship server handshake timeout"))
			return
		}
		c.handshakeInit_cmiStateServerWait(message)

	// smeHello

	case model.SmeHelloState:
		// check if the service is already trusted, auto accept is true or the role is client,
		// which means it was initiated from this service usually by triggering the
		// pairing service
		// go to substate ready if so, otherwise to substate pending

		if c.infoProvider.IsRemoteServiceForSKIPaired(c.remoteSKI) ||
			c.infoProvider.IsAutoAcceptEnabled() ||
			c.role == ShipRoleClient {
			c.setState(model.SmeHelloStateReadyInit, nil)
		} else {
			c.setState(model.SmeHelloStatePendingInit, nil)
		}
		c.handleState(timeout, message)

	case model.SmeHelloStateReadyInit:
		c.handshakeHello_Init()

	case model.SmeHelloStateReadyListen:
		c.handshakeHello_ReadyListen(timeout, message)

	case model.SmeHelloStatePendingInit:
		c.handshakeHello_PendingInit()

	case model.SmeHelloStatePendingListen:
		c.handshakeHello_PendingListen(timeout, message)

	case model.SmeHelloStateOk:
		c.handshakeProtocol_Init()

	case model.SmeHelloStateAbort:
		c.handshakeHello_Abort()

	case model.SmeHelloStateAbortDone, model.SmeHelloStateRemoteAbortDone:
		go func() {
			<-time.After(time.Second)
			c.CloseConnection(false, 4452, "Node rejected by application")
		}()

	// smeProtocol

	case model.SmeProtHStateServerListenProposal:
		c.handshakeProtocol_smeProtHStateServerListenProposal(message)

	case model.SmeProtHStateServerListenConfirm:
		c.handshakeProtocol_smeProtHStateServerListenConfirm(message)

	case model.SmeProtHStateClientListenChoice:
		c.stopHandshakeTimer()
		c.handshakeProtocol_smeProtHStateClientListenChoice(message)

	case model.SmeProtHStateClientOk:
		c.setAndHandleState(model.SmePinStateCheckInit)

	case model.SmeProtHStateServerOk:
		c.setAndHandleState(model.SmePinStateCheckInit)

	// smePinState

	case model.SmePinStateCheckInit:
		c.handshakePin_Init()

	case model.SmePinStateCheckListen, model.SmePinStateAskInit, model.SmePinStateAskProcess:
		if timeout {
			c.endHandshakeWithError(api.ErrPINProtocol)
			return
		}
		c.handshakePin_smePinStateCheckListen(message)

	case model.SmePinStateCheckOk, model.SmePinStateAskRestricted, model.SmePinStateAskOk:
		c.handshakeAccessMethods_Init()

	// smeAccessMethods

	case model.SmeAccessMethodsRequest:
		c.handshakeAccessMethods_Request(message)
	}
}

// set a state and trigger handling it
func (c *ShipConnection) setAndHandleState(state model.ShipMessageExchangeState) {
	if !c.setState(state, nil) {
		return
	}
	c.handleState(false, nil)
}

// SHIP handshake is approved, now set the new state and the SPINE read handler
func (c *ShipConnection) approveHandshake() {
	c.pairingApprovalMux.Lock()
	if c.pairingClosing || c.pairingTerminal || c.spineSetupStarted {
		c.pairingApprovalMux.Unlock()
		return
	}
	if c.requirePairingApproval {
		if !c.pairingCommitStarted || !c.pairingApprovalRequested || c.pairingApprovalReleased {
			c.pairingApprovalMux.Unlock()
			return
		}
		c.pairingApprovalReleased = true
	}
	c.spineSetupStarted = true
	c.pairingApprovalMux.Unlock()

	// Report to SPINE local device about this remote device connection
	var reader api.ShipConnectionDataReaderInterface
	c.runPairingEffect(func() {
		if c.pairingEffectAllowed() {
			reader = c.infoProvider.SetupRemoteDevice(c.remoteSKI, c)
		}
	}, true)
	if reader == nil {
		c.CloseConnection(false, 4452, "SPINE reader unavailable")
		return
	}
	c.stopHandshakeTimer()

	c.spineDispatchMux.Lock()
	c.pairingApprovalMux.Lock()
	if c.pairingClosing || c.pairingTerminal {
		c.pairingApprovalMux.Unlock()
		c.spineDispatchMux.Unlock()
		return
	}
	c.mux.Lock()
	oldState := c.smeState
	c.smeState = model.SmeStateComplete
	c.smeError = nil
	c.bufferMux.Lock()
	c.dataReader = reader
	buffered := c.spineBuffer
	c.spineBuffer = nil
	c.spineBufferBytes = 0
	c.bufferMux.Unlock()
	c.mux.Unlock()

	var tasks []func()
	if oldState != model.SmeStateComplete {
		tasks = append(tasks, func() {
			if c.spineDispatchTerminated() {
				return
			}
			logging.Log().Trace(c.RemoteSKI(), "SHIP state changed to:", model.SmeStateComplete)
			c.reportShipHandshakeStateUpdate(model.ShipState{State: model.SmeStateComplete})
		})
	}
	for _, item := range buffered {
		payload := append([]byte(nil), item...)
		tasks = append(tasks, func() {
			if !c.spineDispatchTerminated() {
				reader.HandleShipPayloadMessage(payload)
			}
		})
	}
	shouldDrain := c.enqueueSpineDispatchLocked(tasks...)
	c.pairingApprovalMux.Unlock()
	c.spineDispatchMux.Unlock()
	if shouldDrain {
		c.drainSpineDispatchQueue()
	}
}

// end the handshake process because of an error
func (c *ShipConnection) endHandshakeWithError(err error) {
	c.stopHandshakeTimer()
	c.discardTransientPIN()
	c.setPINFailureFor(err)

	if c.testHooks != nil && c.testHooks.beforeHandshakeErrorState != nil {
		c.testHooks.beforeHandshakeErrorState()
	}
	if !c.setState(model.SmeStateError, err) {
		return
	}

	logging.Log().Debug(c.RemoteSKI(), "SHIP handshake error:", err)

	c.CloseConnection(true, 0, err.Error())
}

// set the handshake timer to a new duration and start the channel
func (c *ShipConnection) setHandshakeTimer(timerType timeoutTimerType, duration time.Duration) {
	c.stopHandshakeTimer()

	stopChan := make(chan struct{})
	doneChan := make(chan struct{})
	c.handshakeTimerMux.Lock()
	if c.shutdownRequested() {
		c.handshakeTimerMux.Unlock()
		return
	}
	c.handshakeTimerRunning = true
	c.handshakeTimerType = timerType
	c.handshakeTimerDuration = duration
	c.handshakeTimerStopChan = stopChan
	c.handshakeTimerDoneChan = doneChan
	c.handshakeTimerActive++
	c.handshakeTimerMux.Unlock()

	go func() {
		defer close(doneChan)
		defer c.finishHandshakeTimer()
		timer := time.NewTimer(duration)
		defer timer.Stop()

		select {
		case <-stopChan:
			return
		case <-timer.C:
			c.handshakeTimerMux.Lock()
			if c.handshakeTimerStopChan != stopChan || !c.handshakeTimerRunning {
				c.handshakeTimerMux.Unlock()
				return
			}
			c.handshakeTimerRunning = false
			c.handshakeTimerMux.Unlock()
			c.handleState(true, nil)
			return
		}
	}()
}

// stopHandshakeTimer reliably revokes the current timer generation. It does
// not wait because timeout handlers may transition into states that stop or
// replace their own timer.
func (c *ShipConnection) stopHandshakeTimer() {
	c.handshakeTimerMux.Lock()
	stopChan := c.handshakeTimerStopChan
	doneChan := c.handshakeTimerDoneChan
	wasRunning := c.handshakeTimerRunning
	if stopChan != nil {
		c.handshakeTimerStopChan = nil
		close(stopChan)
	}
	c.handshakeTimerRunning = false
	c.handshakeTimerMux.Unlock()

	if wasRunning && doneChan != nil {
		<-doneChan
	}
}

// stopHandshakeTimerAndWait is the teardown barrier for owners that must not
// release callback dependencies until all timer generations have exited.
func (c *ShipConnection) stopHandshakeTimerAndWait() {
	for {
		c.stopHandshakeTimer()
		c.handshakeTimerMux.Lock()
		if c.handshakeTimerActive == 0 {
			c.handshakeTimerMux.Unlock()
			return
		}
		c.handshakeTimerIdle.Wait()
		c.handshakeTimerMux.Unlock()
	}
}

func (c *ShipConnection) finishHandshakeTimer() {
	c.handshakeTimerMux.Lock()
	c.handshakeTimerActive--
	c.handshakeTimerIdle.Broadcast()
	c.handshakeTimerMux.Unlock()
}

func (c *ShipConnection) handshakeTimerCallbacksActive() bool {
	c.handshakeTimerMux.Lock()
	defer c.handshakeTimerMux.Unlock()
	return c.handshakeTimerActive > 0
}

func (c *ShipConnection) setHandshakeTimerRunning(value bool) {
	c.handshakeTimerMux.Lock()
	defer c.handshakeTimerMux.Unlock()

	c.handshakeTimerRunning = value
}

func (c *ShipConnection) getHandshakeTimerRunning() bool {
	c.handshakeTimerMux.Lock()
	defer c.handshakeTimerMux.Unlock()

	return c.handshakeTimerRunning
}

func (c *ShipConnection) setHandshakeTimerType(timerType timeoutTimerType) {
	c.handshakeTimerMux.Lock()
	defer c.handshakeTimerMux.Unlock()

	c.handshakeTimerType = timerType
}

func (c *ShipConnection) getHandshakeTimerType() timeoutTimerType {
	c.handshakeTimerMux.Lock()
	defer c.handshakeTimerMux.Unlock()

	return c.handshakeTimerType
}
