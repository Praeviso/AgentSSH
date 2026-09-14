package main

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"gopkg.in/yaml.v3"
)

func TestPlanTemplateComposeWritesReviewablePlan(t *testing.T) {
	archivePath := writeTemplateTar(t, map[string]string{
		"app/main.js":      "console.log('ok')\n",
		"app/package.json": "{}\n",
	})
	output := filepath.Join(t.TempDir(), "deploy.yaml")
	cmd := newPlanTemplateCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"compose",
		"--cwd", "/opt/app",
		"--service", "web",
		"--compose-file", "compose.yaml",
		"--compose-file", "compose.production.yaml",
		"--revision", "rev123",
		"--archive", archivePath,
		"--local-health-url", "http://127.0.0.1:8080/health",
		"--public-health-url", "https://example.com/health",
		"--health-timeout", "5s",
		"--output", output,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("template compose: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var spec planSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse template: %v\n%s", err, data)
	}
	if spec.Version != 1 || spec.Metadata.Revision != "rev123" {
		t.Fatalf("metadata = %#v", spec.Metadata)
	}
	if len(spec.Commands) != 12 {
		t.Fatalf("commands=%d want 12:\n%s", len(spec.Commands), data)
	}
	upload := spec.Commands[0]
	if upload.ID != "upload-archive" || upload.CWD != "/opt/app" || upload.StdinFile == archivePath || !filepath.IsAbs(upload.StdinFile) {
		t.Fatalf("upload step = %#v", upload)
	}
	if sidecar, err := os.ReadFile(upload.StdinFile); err != nil {
		t.Fatalf("read sidecar: %v", err)
	} else if original, err := os.ReadFile(archivePath); err != nil || !bytes.Equal(sidecar, original) {
		t.Fatalf("sidecar does not match original err=%v", err)
	}
	assertSHA := findTemplateCommand(t, spec.Commands, "assert-upload-sha256")
	if !strings.Contains(strings.Join(assertSHA.Argv, " "), "sha256sum -c -") || assertSHA.OnFailure != executionOnFailureStop {
		t.Fatalf("sha step = %#v", assertSHA)
	}
	backup := findTemplateCommand(t, spec.Commands, "backup-current-files")
	backupShell := strings.Join(backup.Argv, " ")
	for _, want := range []string{"files-existing.txt", "files-missing.txt", "files-existing.null", "files-before.contents.txt", "--null --verbatim-files-from", "for p in 'app/main.js' 'app/package.json'"} {
		if !strings.Contains(backupShell, want) {
			t.Fatalf("backup step missing %q: %#v", want, backup)
		}
	}
	if !strings.Contains(spec.Metadata.Recovery, "empty backup") || !strings.Contains(spec.Metadata.Recovery, "missing-file list") {
		t.Fatalf("recovery text is not honest about backup limits: %q", spec.Metadata.Recovery)
	}
	build := findTemplateCommand(t, spec.Commands, "build-service")
	wantBuild := []string{"docker", "compose", "-f", "/opt/app/compose.yaml", "-f", "/opt/app/compose.production.yaml", "build", "web"}
	if !slices.Equal(build.Argv, wantBuild) || build.CWD != "/opt/app" || build.OnFailure != executionOnFailureStop {
		t.Fatalf("build step = %#v", build)
	}
	verify := findTemplateCommand(t, spec.Commands, "collect-compose-logs")
	if verify.Phase != executionStepVerify || verify.OnFailure != executionOnFailureContinue {
		t.Fatalf("verify step = %#v", verify)
	}
	parsed, err := readPlanDocument(output)
	if err != nil {
		t.Fatalf("read generated plan: %v", err)
	}
	task := approval.TaskCandidate(parsed.Commands[5].Cmd, "")
	if task == nil || task.Profile != "compose-maintenance" || !slices.Equal(task.Compose, []string{"docker", "compose", "-f", "/opt/app/compose.yaml", "-f", "/opt/app/compose.production.yaml"}) || !slices.Contains(task.Resources, "web") {
		t.Fatalf("build task identity = %#v cmd=%q", task, parsed.Commands[5].Cmd)
	}
	healthTask := approval.TaskCandidate(parsed.Commands[10].Cmd, "")
	if healthTask == nil || healthTask.Profile != "http-probe" || !slices.Equal(healthTask.Resources, []string{"http://127.0.0.1:8080/health"}) {
		t.Fatalf("health task identity = %#v cmd=%q", healthTask, parsed.Commands[10].Cmd)
	}
}

func TestPlanTemplateBackupCommandShellBehavior(t *testing.T) {
	memberPaths := []string{"app/main.js", "app/package.json"}
	archive := archiveTemplateInfo{
		SidecarPath: "/tmp/release.tar",
		Members:     len(memberPaths),
		MemberPaths: memberPaths,
		Bytes:       1024,
		Expanded:    64,
		SHA256:      strings.Repeat("a", 64),
	}
	opts := planTemplateComposeOptions{
		CWD:           "/opt/app",
		Service:       "web",
		ComposeFiles:  []string{"compose.yaml"},
		Revision:      "rev",
		HealthTimeout: "10",
	}
	backupStep := findTemplateCommand(t, composeDeploymentTemplate(opts, archive).Commands, "backup-current-files")
	if len(backupStep.Argv) != 3 || backupStep.Argv[0] != "sh" || backupStep.Argv[1] != "-c" {
		t.Fatalf("backup argv = %#v", backupStep.Argv)
	}

	t.Run("all missing creates empty backup and missing list", func(t *testing.T) {
		root := t.TempDir()
		runBackupShell(t, root, backupStep.Argv)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-existing.txt", nil)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-missing.txt", memberPaths)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-before.contents.txt", nil)
		if _, err := os.Stat(filepath.Join(root, ".agentssh-deploy/rev.web.files-before.tar")); err != nil {
			t.Fatalf("empty backup tar missing: %v", err)
		}
	})

	t.Run("partial existing records both lists and backup contents", func(t *testing.T) {
		root := t.TempDir()
		mustWriteTemplateFile(t, root, "app/main.js", "old main")
		runBackupShell(t, root, backupStep.Argv)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-existing.txt", []string{"app/main.js"})
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-missing.txt", []string{"app/package.json"})
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-before.contents.txt", []string{"app/main.js"})
	})

	t.Run("all existing records full backup contents", func(t *testing.T) {
		root := t.TempDir()
		mustWriteTemplateFile(t, root, "app/main.js", "old main")
		mustWriteTemplateFile(t, root, "app/package.json", "{}")
		runBackupShell(t, root, backupStep.Argv)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-existing.txt", memberPaths)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-missing.txt", nil)
		assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-before.contents.txt", memberPaths)
	})

	t.Run("existing non regular path stops", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "app/main.js"), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(backupStep.Argv[0], backupStep.Argv[1:]...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "non-regular") {
			t.Fatalf("backup shell err=%v out=%s", err, out)
		}
	})
}

func TestPlanTemplateBackupCommandHandlesSpecialFilenames(t *testing.T) {
	memberPaths := []string{"-C", "dir/back\\slash.txt", "dir/with space.txt"}
	command := backupCurrentFilesCommand(
		".agentssh-deploy/rev.web.files-before.tar",
		".agentssh-deploy/rev.web.files-existing.txt",
		".agentssh-deploy/rev.web.files-missing.txt",
		".agentssh-deploy/rev.web.files-existing.null",
		".agentssh-deploy/rev.web.files-before.contents.txt",
		memberPaths,
	)
	root := t.TempDir()
	for _, name := range memberPaths {
		mustWriteTemplateFile(t, root, name, "old "+name)
	}
	runBackupShell(t, root, []string{"sh", "-c", command})
	assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-existing.txt", memberPaths)
	assertTemplateFileLines(t, root, ".agentssh-deploy/rev.web.files-missing.txt", nil)

	extractRoot := filepath.Join(root, "extract")
	if err := os.MkdirAll(extractRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("tar", "-xf", filepath.Join(root, ".agentssh-deploy/rev.web.files-before.tar"), "-C", extractRoot)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("extract special backup: %v\n%s", err, out)
	}
	for _, name := range memberPaths {
		data, err := os.ReadFile(filepath.Join(extractRoot, name))
		if err != nil {
			t.Fatalf("read extracted %q: %v", name, err)
		}
		if string(data) != "old "+name {
			t.Fatalf("extracted %q = %q", name, data)
		}
	}
}

func TestPlanTemplateBackupRejectsSymlinkPaths(t *testing.T) {
	memberPaths := []string{"app/main.js"}
	command := backupCurrentFilesCommand(
		".agentssh-deploy/rev.web.files-before.tar",
		".agentssh-deploy/rev.web.files-existing.txt",
		".agentssh-deploy/rev.web.files-missing.txt",
		".agentssh-deploy/rev.web.files-existing.null",
		".agentssh-deploy/rev.web.files-before.contents.txt",
		memberPaths,
	)

	t.Run("member symlink", func(t *testing.T) {
		root := t.TempDir()
		mustWriteTemplateFile(t, root, "target/main.js", "old")
		if err := os.MkdirAll(filepath.Join(root, "app"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../target/main.js", filepath.Join(root, "app/main.js")); err != nil {
			t.Fatal(err)
		}
		out, err := runShellInDir(root, command)
		if err == nil || !strings.Contains(out, "refusing symlink archive path: app/main.js") {
			t.Fatalf("err=%v out=%s", err, out)
		}
	})

	t.Run("parent symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "realapp"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("realapp", filepath.Join(root, "app")); err != nil {
			t.Fatal(err)
		}
		out, err := runShellInDir(root, command)
		if err == nil || !strings.Contains(out, "refusing symlink parent path: app") {
			t.Fatalf("err=%v out=%s", err, out)
		}
	})
}

func TestPlanTemplateApplyRejectsSymlinkBeforeExtraction(t *testing.T) {
	archive := archiveTemplateInfo{
		SidecarPath: "/tmp/release.tar",
		Members:     1,
		MemberPaths: []string{"app/main.js"},
		Bytes:       1024,
		Expanded:    64,
		SHA256:      strings.Repeat("a", 64),
	}
	opts := planTemplateComposeOptions{CWD: "/opt/app", Service: "web", ComposeFiles: []string{"compose.yaml"}, Revision: "rev", HealthTimeout: "10"}
	applyStep := findTemplateCommand(t, composeDeploymentTemplate(opts, archive).Commands, "apply-archive")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".agentssh-deploy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".agentssh-deploy/rev.tar"), []byte("not reached"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "realapp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("realapp", filepath.Join(root, "app")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(applyStep.Argv[0], applyStep.Argv[1:]...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "refusing symlink parent path: app") {
		t.Fatalf("err=%v out=%s", err, out)
	}
}

func TestPlanTemplateComposeRunningAssertionShellBehavior(t *testing.T) {
	command := assertComposeRunningCommand([]string{"-f", "/opt/app/compose.yaml"}, "web")
	for _, tc := range []struct {
		name     string
		scenario string
		wantErr  bool
	}{
		{name: "all healthy", scenario: "healthy"},
		{name: "running with no healthcheck", scenario: "nohealth"},
		{name: "unhealthy fails", scenario: "unhealthy", wantErr: true},
		{name: "mixed replicas fail", scenario: "mixed", wantErr: true},
		{name: "docker nonzero fails", scenario: "nonzero", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			mockDocker := filepath.Join(bin, "docker")
			if err := os.WriteFile(mockDocker, []byte(mockDockerScript), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", command)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "SCENARIO="+tc.scenario)
			out, err := cmd.CombinedOutput()
			if tc.wantErr && err == nil {
				t.Fatalf("expected failure, got success out=%s", out)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected success, err=%v out=%s", err, out)
			}
		})
	}
}

func TestValidateTarArchiveAcceptsLegacyRegularTypeAfterReaderNormalization(t *testing.T) {
	archivePath := writeTemplateTarWithType(t, "legacy.txt", 0, "old regular type")
	info, err := validateTarArchive(archivePath)
	if err != nil {
		t.Fatalf("validate tar with legacy regular type: %v", err)
	}
	if info.Members != 1 || !slices.Equal(info.MemberPaths, []string{"legacy.txt"}) {
		t.Fatalf("archive info = %#v", info)
	}
}

func TestPlanTemplateComposeRejectsInvalidInputs(t *testing.T) {
	validArchive := writeTemplateTar(t, map[string]string{"app.txt": "ok\n"})
	t.Run("output exists", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "deploy.yaml")
		if err := os.WriteFile(output, []byte("exists"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", validArchive,
			"--output", output,
		)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("unsafe service", func(t *testing.T) {
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web;rm",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", validArchive,
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "--service") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("unsafe archive member", func(t *testing.T) {
		archivePath := writeTemplateTar(t, map[string]string{"../escape": "bad\n"})
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", archivePath,
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "safe relative path") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("archive member with leading whitespace", func(t *testing.T) {
		archivePath := writeTemplateTar(t, map[string]string{" app.txt": "bad\n"})
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", archivePath,
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "invalid member name") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("archive member with control character", func(t *testing.T) {
		archivePath := writeTemplateTar(t, map[string]string{"app\tname.txt": "bad\n"})
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", archivePath,
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "invalid member name") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("reserved archive member", func(t *testing.T) {
		archivePath := writeTemplateTar(t, map[string]string{".agentssh-deploy/archive.tar": "bad\n"})
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", archivePath,
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "reserved AgentSSH") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("health timeout too large", func(t *testing.T) {
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", validArchive,
			"--local-health-url", "http://127.0.0.1:8080/health",
			"--health-timeout", "31s",
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "30s") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("health url credentials", func(t *testing.T) {
		err := executePlanTemplate(t,
			"--cwd", "/opt/app",
			"--service", "web",
			"--compose-file", "compose.yaml",
			"--revision", "rev",
			"--archive", validArchive,
			"--local-health-url", "https://user:pass@example.com/health",
			"--output", filepath.Join(t.TempDir(), "deploy.yaml"),
		)
		if err == nil || !strings.Contains(err.Error(), "no credentials") {
			t.Fatalf("err=%v", err)
		}
	})
}

func executePlanTemplate(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newPlanTemplateCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"compose"}, args...))
	return cmd.Execute()
}

func findTemplateCommand(t *testing.T, commands []planCommand, id string) planCommand {
	t.Helper()
	for _, command := range commands {
		if command.ID == id {
			return command
		}
	}
	t.Fatalf("command %s not found", id)
	return planCommand{}
}

func runBackupShell(t *testing.T, root string, argv []string) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("backup shell failed: %v\n%s", err, out)
	}
}

func runShellInDir(root string, command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func assertTemplateFileLines(t *testing.T, root string, relative string, want []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	trimmed := strings.TrimSuffix(string(data), "\n")
	var got []string
	if trimmed != "" {
		got = strings.Split(trimmed, "\n")
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s lines=%#v want %#v", relative, got, want)
	}
}

func mustWriteTemplateFile(t *testing.T, root string, relative string, body string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTemplateTarWithType(t *testing.T, name string, typeflag byte, body string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: typeflag, Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	path := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return path
}

func writeTemplateTar(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	path := filepath.Join(t.TempDir(), "archive.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return path
}

const mockDockerScript = `#!/bin/sh
set -eu
if [ "$1" = "compose" ]; then
  shift
  while [ "$#" -gt 0 ] && [ "$1" = "-f" ]; do
    shift 2
  done
  if [ "$1" = "ps" ] && [ "$2" = "-q" ]; then
    all_flag=0
    if [ "$3" = "--all" ]; then
      all_flag=1
      shift
    fi
    case "$SCENARIO:$all_flag" in
      healthy:1) printf '%s\n%s\n' c1 c2 ;;
      nohealth:1) printf '%s\n' c1 ;;
      unhealthy:1) printf '%s\n' c1 ;;
      mixed:1) printf '%s\n%s\n' c1 c2 ;;
      nonzero:1) exit 42 ;;
      mixed:0) printf '%s\n' c1 ;;
      *) exit 99 ;;
    esac
    exit 0
  fi
fi
if [ "$1" = "inspect" ] && [ "$2" = "--format" ]; then
  format=$3
  id=$4
  case "$format:$SCENARIO:$id" in
    '{{.State.Status}}':healthy:c1|'{{.State.Status}}':healthy:c2|'{{.State.Status}}':nohealth:c1|'{{.State.Status}}':unhealthy:c1|'{{.State.Status}}':mixed:c1) echo running ;;
    '{{.State.Status}}':mixed:c2) echo exited ;;
    '{{if .State.Health}}{{.State.Health.Status}}{{end}}':healthy:c1|'{{if .State.Health}}{{.State.Health.Status}}{{end}}':healthy:c2|'{{if .State.Health}}{{.State.Health.Status}}{{end}}':mixed:c1) echo healthy ;;
    '{{if .State.Health}}{{.State.Health.Status}}{{end}}':nohealth:c1|'{{if .State.Health}}{{.State.Health.Status}}{{end}}':mixed:c2) : ;;
    '{{if .State.Health}}{{.State.Health.Status}}{{end}}':unhealthy:c1) echo unhealthy ;;
    *) exit 98 ;;
  esac
  exit 0
fi
exit 97
`
