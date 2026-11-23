package oidc

import "testing"

func Test_new_sets_openid_configuration_well_known_url(t *testing.T) {
	d := Oidc{}
	if got := d.New().GetWellKnownUrl(); got != "/.well-known/openid-configuration" {
		t.Errorf("unexpected well-known url: %s", got)
	}
}

func Test_zero_value_has_empty_well_known_url(t *testing.T) {
	if got := (Oidc{}).GetWellKnownUrl(); got != "" {
		t.Errorf("expected empty well-known url before New, got %q", got)
	}
}

func Test_new_does_not_mutate_receiver(t *testing.T) {
	d := Oidc{}
	d.New()
	if d.GetWellKnownUrl() != "" {
		t.Errorf("New should return a configured copy and leave the receiver untouched")
	}
}
