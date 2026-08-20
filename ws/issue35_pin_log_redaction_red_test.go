package ws

import (
	"strings"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

func TestIssue35PINInputIsRedactedBeforeWebsocketLogging(t *testing.T) {
	const secret = "12aBc34D"
	message := append(
		[]byte{model.MsgTypeControl},
		[]byte(`{"connectionPinInput":[{"pin":"`+secret+`"}]}`)...,
	)

	text := (&WebsocketConnection{}).textFromMessage(message)
	if strings.Contains(text, secret) {
		t.Fatalf("PIN logging text disclosed secret: %q", text)
	}
	if text != "ship control: connectionPinInput [redacted]" {
		t.Fatalf("PIN logging text = %q, want categorical redaction", text)
	}
}
