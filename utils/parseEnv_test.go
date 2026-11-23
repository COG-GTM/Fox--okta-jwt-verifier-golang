package utils

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var parseEnvKeys = []string{"CLIENT_ID", "ISSUER", "USERNAME", "PASSWORD"}

func inTempDir(t *testing.T, envFile string) func() {
	dir, err := ioutil.TempDir("", "parseenv")
	if err != nil {
		t.Fatalf("could not create temp dir: %s", err)
	}
	if envFile != "" {
		if err := ioutil.WriteFile(filepath.Join(dir, ".env"), []byte(envFile), 0600); err != nil {
			t.Fatalf("could not write .env: %s", err)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("could not get working dir: %s", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("could not chdir: %s", err)
	}

	saved := map[string]string{}
	for _, k := range parseEnvKeys {
		if v, ok := os.LookupEnv(k); ok {
			saved[k] = v
		}
		os.Unsetenv(k)
	}

	return func() {
		os.Chdir(wd)
		os.RemoveAll(dir)
		for _, k := range parseEnvKeys {
			os.Unsetenv(k)
			if v, ok := saved[k]; ok {
				os.Setenv(k, v)
			}
		}
	}
}

func Test_set_env_variable_reads_value_from_env_file(t *testing.T) {
	defer inTempDir(t, "CLIENT_ID=abc123\nISSUER=https://issuer.example.com\n")()

	setEnvVariable("CLIENT_ID", "")
	setEnvVariable("ISSUER", "")

	if got := os.Getenv("CLIENT_ID"); got != "abc123" {
		t.Errorf("expected CLIENT_ID from .env, got %q", got)
	}
	if got := os.Getenv("ISSUER"); got != "https://issuer.example.com" {
		t.Errorf("expected ISSUER from .env, got %q", got)
	}
}

func Test_set_env_variable_keeps_existing_value(t *testing.T) {
	defer inTempDir(t, "CLIENT_ID=from-file\n")()
	os.Setenv("CLIENT_ID", "from-env")

	setEnvVariable("CLIENT_ID", os.Getenv("CLIENT_ID"))

	if got := os.Getenv("CLIENT_ID"); got != "from-env" {
		t.Errorf("expected existing CLIENT_ID to be kept, got %q", got)
	}
}

func Test_set_env_variable_ignores_other_keys(t *testing.T) {
	defer inTempDir(t, "ISSUER=https://issuer.example.com\n")()

	setEnvVariable("CLIENT_ID", "")

	if _, ok := os.LookupEnv("CLIENT_ID"); ok {
		t.Errorf("CLIENT_ID should not be set when absent from .env")
	}
}

func Test_set_env_variable_without_env_file_is_noop(t *testing.T) {
	defer inTempDir(t, "")()

	setEnvVariable("CLIENT_ID", "")

	if _, ok := os.LookupEnv("CLIENT_ID"); ok {
		t.Errorf("CLIENT_ID should not be set without a .env file")
	}
}

func Test_parse_environment_loads_values_from_env_file(t *testing.T) {
	defer inTempDir(t, "CLIENT_ID=abc123\nISSUER=https://issuer.example.com\nUSERNAME=user\nPASSWORD=pass\n")()

	ParseEnvironment()

	want := map[string]string{
		"CLIENT_ID": "abc123",
		"ISSUER":    "https://issuer.example.com",
		"USERNAME":  "user",
		"PASSWORD":  "pass",
	}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("expected %s=%q, got %q", k, v, got)
		}
	}
}

func Test_parse_environment_uses_global_env_without_env_file(t *testing.T) {
	defer inTempDir(t, "")()
	os.Setenv("CLIENT_ID", "abc123")
	os.Setenv("ISSUER", "https://issuer.example.com")

	ParseEnvironment()

	if os.Getenv("CLIENT_ID") != "abc123" || os.Getenv("ISSUER") != "https://issuer.example.com" {
		t.Errorf("global environment variables were not preserved")
	}
}

// ParseEnvironment calls os.Exit, so the exit paths run in a child test process.
func Test_parse_environment_exits_when_required_variables_missing(t *testing.T) {
	if os.Getenv("PARSE_ENV_HELPER") == "1" {
		defer inTempDir(t, os.Getenv("PARSE_ENV_FILE"))()
		ParseEnvironment()
		return
	}

	cases := []struct {
		name    string
		envFile string
		wantLog string
	}{
		{"missing client id", "ISSUER=https://issuer.example.com\n", "Could not resolve a CLIENT_ID environment variable."},
		{"missing issuer", "CLIENT_ID=abc123\n", "Could not resolve a ISSUER environment variable."},
	}

	for _, c := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^Test_parse_environment_exits_when_required_variables_missing$")
		cmd.Env = append(os.Environ(), "PARSE_ENV_HELPER=1", "PARSE_ENV_FILE="+c.envFile)
		out, err := cmd.CombinedOutput()

		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.Success() {
			t.Errorf("%s: expected non-zero exit, got %v", c.name, err)
		}
		if !strings.Contains(string(out), c.wantLog) {
			t.Errorf("%s: expected log %q, got %s", c.name, c.wantLog, out)
		}
	}
}
