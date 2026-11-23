package errors

import "testing"

func Test_jwt_empty_string_error_message(t *testing.T) {
	var err error = JwtEmptyStringError()
	if err.Error() != "you must provide a jwt to verify" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func Test_jwt_empty_string_error_returns_new_instance(t *testing.T) {
	if JwtEmptyStringError() == JwtEmptyStringError() {
		t.Errorf("expected a new error instance on each call")
	}
}
