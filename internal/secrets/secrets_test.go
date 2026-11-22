package secrets

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestParse(t *testing.T) {
	for _, ok := range []string{"env:X", "keychain:svc/acct", "keepassxc:/a/b.kdbx#CI/Release/key"} {
		r, err := Parse(ok)
		if err != nil || r.String() != ok {
			t.Errorf("%s: %v %v", ok, r, err)
		}
	}
	for _, bad := range []string{"", "X", "file:/tmp/key", "keychain:svc", "keepassxc:/a.kdbx", "env:"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("HIVE_TEST_SECRET", "  abc  ")
	v, err := Get("env:HIVE_TEST_SECRET", nil)
	if err != nil || string(v) != "abc" {
		t.Fatalf("%q %v", v, err)
	}
	Wipe(v)
	if string(v) != "\x00\x00\x00" {
		t.Fatal("not wiped")
	}
	os.Unsetenv("HIVE_TEST_SECRET_EMPTY")
	if _, err := Get("env:HIVE_TEST_SECRET_EMPTY", nil); err == nil {
		t.Fatal("empty variable accepted")
	}
}

func TestKeePassNeedsUnlock(t *testing.T) {
	if _, err := Get("keepassxc:/nonexistent.kdbx#x", nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v", err)
	}
}

func TestKeychain(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("HIVE_TEST_KEYCHAIN") == "" {
		t.Skip("set HIVE_TEST_KEYCHAIN=1 on macOS to write a test item into the login keychain")
	}
	const svc, acct = "anthophila-hive-test", "unit"
	defer DeleteKeychain(svc, acct)
	if err := StoreKeychain(svc, acct, []byte("c2VjcmV0LXZhbHVl")); err != nil {
		t.Fatal(err)
	}
	v, err := Get("keychain:"+svc+"/"+acct, nil)
	if err != nil || string(v) != "c2VjcmV0LXZhbHVl" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestRedactor(t *testing.T) {
	var r Redactor
	r.Add([]byte("tok_123456"))
	r.Add([]byte("abc"))
	if got := r.Clean("push https://x:tok_123456@h failed; abc"); got != "push https://x:***@h failed; abc" {
		t.Fatal(got)
	}
}
