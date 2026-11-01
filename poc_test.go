package main

import (
	"encoding/json"
	"net/url"
	"testing"
)

// Mirrors calendar/remote/subscription.go ClientState field.
type Subscription struct {
	ID          string `json:"id"`
	ClientState string `json:"clientState,omitempty"`
}

// Mirrors processNotification ClientState gate (engine/notification.go:132-133).
func unauthorizedWebhook(stored, incoming string) bool {
	return stored != "" && stored != incoming
}

// Mirrors msgraph/call.go absolute-URL short-circuit (scheme+host present → no base join).
func usesAbsoluteURL(path string) bool {
	pathURL, err := url.Parse(path)
	if err != nil {
		return false
	}
	return pathURL.Scheme != "" && pathURL.Host != ""
}

func TestCreateReusesStructPreservesClientState(t *testing.T) {
	// CreateMySubscription: POST into same *sub that already has ClientState set.
	sub := &Subscription{ClientState: "secret-from-newRandomString"}
	// Graph create/list responses commonly omit clientState (write-oriented / not returned).
	if err := json.Unmarshal([]byte(`{"id":"sub-guid-1","resource":"me/events"}`), sub); err != nil {
		t.Fatal(err)
	}
	if sub.ClientState != "secret-from-newRandomString" {
		t.Fatalf("create path should keep pre-set ClientState when Graph omits field; got %q", sub.ClientState)
	}
	if unauthorizedWebhook(sub.ClientState, "attacker") {
		// expected: still authorized-check fails for attacker
	} else {
		t.Fatal("expected attacker ClientState to be rejected while secret retained")
	}
	if !unauthorizedWebhook(sub.ClientState, "attacker") {
		t.Fatal("expected unauthorized")
	}
}

func TestRenewFreshStructWipesClientStateWhenGraphOmits(t *testing.T) {
	// RenewSubscription: unmarshals PATCH into a NEW zero Subscription{}, then stores it.
	// notification.go then StoreUserSubscription(creator, {Remote: renewed}).
	old := &Subscription{ID: "sub-guid-1", ClientState: "secret-from-newRandomString"}
	renewed := Subscription{} // zero — as in msgraph/subscription.go RenewSubscription
	// Docs/SO: clientState often absent/null on GET/PATCH response bodies.
	if err := json.Unmarshal([]byte(`{"id":"sub-guid-1","expirationDateTime":"2099-01-01T00:00:00Z"}`), &renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.ClientState != "" {
		t.Fatalf("expected empty ClientState after renew unmarshal omit, got %q", renewed.ClientState)
	}
	// Sibling create kept the secret; renew overwrote store with wiped Remote.
	_ = old
	if unauthorizedWebhook(renewed.ClientState, "") {
		t.Fatal("empty stored ClientState must skip gate (bug)")
	}
	if unauthorizedWebhook(renewed.ClientState, "anything-attacker-sends") {
		t.Fatal("empty stored ClientState must accept any incoming ClientState (auth bypass)")
	}
}

func TestGetNotificationDataAbsoluteResourceIsSSRFPivot(t *testing.T) {
	// get_notification_data.go: CallJSON(GET, wh.Resource, ...) with attacker-controlled Resource
	// after ClientState gate is skipped. call.go uses absolute URL as-is; httpClient is
	// oauth2.NewClient → Authorization: Bearer <victim> sent to attacker host.
	if !usesAbsoluteURL("https://attacker.example/collect") {
		t.Fatal("absolute resource must bypass Graph base join")
	}
	if usesAbsoluteURL("Users/x/Events/y") {
		t.Fatal("relative Graph path should not be treated as absolute")
	}
}

func TestRenewNullClientStateAlsoWipes(t *testing.T) {
	renewed := Subscription{ClientState: "should-be-cleared-if-we-had-set-it"}
	renewed = Subscription{} // renew path
	if err := json.Unmarshal([]byte(`{"id":"sub-guid-1","clientState":null}`), &renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.ClientState != "" {
		t.Fatalf("null clientState should yield empty, got %q", renewed.ClientState)
	}
	if unauthorizedWebhook(renewed.ClientState, "x") {
		t.Fatal("bypass expected")
	}
}
