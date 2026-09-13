package commandline

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCompoundCommandCannotRunWhenCWDFails(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "must-not-exist")
	command, err := Shell("printf first; touch "+Quote(marker)+" # trailing comment", filepath.Join(root, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("sh", "-c", command).Run(); err == nil {
		t.Fatal("missing cwd unexpectedly succeeded")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("compound command escaped failed cwd: %v", err)
	}
	command, err = Shell("printf first; printf second # trailing comment", root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil || string(out) != "firstsecond" {
		t.Fatalf("compound execution %q %v", out, err)
	}
}

func TestArgvExecutableIsNotAnEnvironmentAssignment(t *testing.T) {
	command, err := Render([]string{"AGENTSSH_TEST_ASSIGNMENT=value", "printf", "should-not-run"}, "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", command).Output()
	if err == nil || len(out) != 0 {
		t.Fatalf("argv executable interpreted as shell assignment: %q %v", out, err)
	}
	command, err = Render([]string{"if"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if command != "'if'" {
		t.Fatalf("reserved command name was not quoted: %s", command)
	}
}

func TestLiteralArgumentsRoundTrip(t *testing.T) {
	argv := []string{"printf", "%s", "a b", "", "it's literal", "$(touch /tmp/no)", "a; b | c", "\\"}
	command, err := Render(argv, "/opt/my app")
	if err != nil {
		t.Fatal(err)
	}
	got, cwd, err := Parse(command)
	if err != nil {
		t.Fatal(err)
	}
	if cwd != "/opt/my app" || !reflect.DeepEqual(argv, got) {
		t.Fatalf("round trip: %q %q", cwd, got)
	}
}

func TestParseRejectsExecutableShellSyntax(t *testing.T) {
	for _, command := range []string{"id; whoami", "id | cat", "echo $(id)", "echo `id`", "echo \"$HOME\"", "id > /tmp/x", "echo *", "id\nwhoami", "cd /tmp && id && whoami", "cd relative && id", "env A=x id", ""} {
		_, _, err := Parse(command)
		// env is literal syntax; operation validators reject its semantics.
		if command == "env A=x id" {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil {
			t.Errorf("accepted %q", command)
		}
	}
}

func FuzzLiteralRoundTrip(f *testing.F) {
	for _, s := range []string{"a b", "x'y", "$(bad)", "", "中文"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		command, err := Render([]string{"echo", value}, "")
		if err != nil {
			return
		}
		argv, _, err := Parse(command)
		// Control characters are renderable for exact execution, but excluded
		// from the narrower syntax accepted by task permissions.
		for _, r := range value {
			if r < 32 || r == 127 {
				return
			}
		}
		if err != nil || !reflect.DeepEqual(argv, []string{"echo", value}) {
			t.Fatalf("%q -> %q, %v", value, argv, err)
		}
	})
}
