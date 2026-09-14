package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var templateSafeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

const (
	maxTemplateArchiveMembers       = 512
	maxTemplateArchiveExpandedBytes = int64(maxStdinBytes)
)

type planTemplateComposeOptions struct {
	CWD              string
	Service          string
	ComposeFiles     []string
	Revision         string
	Archive          string
	Output           string
	LocalHealthURLs  []string
	PublicHealthURLs []string
	HealthTimeout    string
}

func newPlanTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Generate reviewable plan YAML templates without submitting or executing.",
	}
	var opts planTemplateComposeOptions
	composeCmd := &cobra.Command{
		Use:   "compose --cwd <remote-dir> --service <name> --compose-file <file>... --revision <rev> --archive <local.tar[.gz]> --output <plan.yaml>",
		Short: "Generate a reviewable Docker Compose deployment plan.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPlanTemplateCompose(opts)
		},
	}
	composeCmd.Flags().StringVar(&opts.CWD, "cwd", "", "absolute remote working directory")
	composeCmd.Flags().StringVar(&opts.Service, "service", "", "Compose service to build, start, and verify")
	composeCmd.Flags().StringArrayVar(&opts.ComposeFiles, "compose-file", nil, "Compose file path relative to --cwd or absolute; repeat to preserve overlay order")
	composeCmd.Flags().StringVar(&opts.Revision, "revision", "", "operator-visible revision label used in artifact names")
	composeCmd.Flags().StringVar(&opts.Archive, "archive", "", "local tar or tar.gz archive to upload through stdin_file")
	composeCmd.Flags().StringVar(&opts.Output, "output", "", "plan YAML path to create; must not already exist")
	composeCmd.Flags().StringArrayVar(&opts.LocalHealthURLs, "local-health-url", nil, "optional fixed health URL checked from the remote host")
	composeCmd.Flags().StringArrayVar(&opts.PublicHealthURLs, "public-health-url", nil, "optional fixed public health URL checked from the remote host")
	composeCmd.Flags().StringVar(&opts.HealthTimeout, "health-timeout", "10s", "per-health-check timeout, e.g. 10s")
	cmd.AddCommand(composeCmd)
	return cmd
}

func runPlanTemplateCompose(opts planTemplateComposeOptions) error {
	archiveInfo, err := validateComposeTemplateOptions(&opts)
	if err != nil {
		return err
	}
	if err := copyValidatedArchiveToSidecar(archiveInfo); err != nil {
		return err
	}
	createdSidecar := true
	defer func() {
		if createdSidecar {
			_ = os.Remove(archiveInfo.SidecarPath)
		}
	}()
	spec := composeDeploymentTemplate(opts, archiveInfo)
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	if err := writeNewFile(opts.Output, data); err != nil {
		return err
	}
	createdSidecar = false
	return nil
}

type archiveTemplateInfo struct {
	Path        string
	SidecarPath string
	Gzip        bool
	Members     int
	MemberPaths []string
	Bytes       int64
	Expanded    int64
	SHA256      string
}

func validateComposeTemplateOptions(opts *planTemplateComposeOptions) (archiveTemplateInfo, error) {
	opts.CWD = strings.TrimSpace(opts.CWD)
	opts.Service = strings.TrimSpace(opts.Service)
	opts.Revision = strings.TrimSpace(opts.Revision)
	opts.Archive = strings.TrimSpace(opts.Archive)
	opts.Output = strings.TrimSpace(opts.Output)
	if opts.CWD == "" || !path.IsAbs(opts.CWD) || strings.ContainsAny(opts.CWD, "\x00\r\n") {
		return archiveTemplateInfo{}, newUsageError("--cwd must be an absolute remote path")
	}
	opts.CWD = path.Clean(opts.CWD)
	if !templateSafeToken.MatchString(opts.Service) {
		return archiveTemplateInfo{}, newUsageError("--service must start with a letter or digit and contain only letters, digits, _, ., or -")
	}
	if !templateSafeToken.MatchString(opts.Revision) {
		return archiveTemplateInfo{}, newUsageError("--revision must start with a letter or digit and contain only letters, digits, _, ., or -")
	}
	if len(opts.ComposeFiles) == 0 {
		return archiveTemplateInfo{}, newUsageError("at least one --compose-file is required")
	}
	for i := range opts.ComposeFiles {
		opts.ComposeFiles[i] = strings.TrimSpace(opts.ComposeFiles[i])
		if err := validateComposeFilePath(opts.ComposeFiles[i]); err != nil {
			return archiveTemplateInfo{}, err
		}
	}
	if opts.Archive == "" {
		return archiveTemplateInfo{}, newUsageError("--archive is required")
	}
	archivePath, err := filepath.Abs(opts.Archive)
	if err != nil {
		return archiveTemplateInfo{}, err
	}
	info, err := validateTarArchive(archivePath)
	if err != nil {
		return archiveTemplateInfo{}, err
	}
	opts.Archive = archivePath
	if opts.Output == "" {
		return archiveTemplateInfo{}, newUsageError("--output is required")
	}
	if _, err := os.Stat(opts.Output); err == nil {
		return archiveTemplateInfo{}, newUsageError("--output %s already exists", opts.Output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return archiveTemplateInfo{}, err
	}
	sidecarPath, err := archiveSidecarPath(opts.Output, opts.Revision, info.SHA256, archivePath)
	if err != nil {
		return archiveTemplateInfo{}, err
	}
	if _, err := os.Stat(sidecarPath); err == nil {
		return archiveTemplateInfo{}, newUsageError("validated archive copy %s already exists", sidecarPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return archiveTemplateInfo{}, err
	}
	info.SidecarPath = sidecarPath
	timeout, err := parseHealthTimeout(opts.HealthTimeout)
	if err != nil {
		return archiveTemplateInfo{}, err
	}
	opts.HealthTimeout = timeout
	for _, raw := range append(append([]string(nil), opts.LocalHealthURLs...), opts.PublicHealthURLs...) {
		if err := validateHealthURL(raw); err != nil {
			return archiveTemplateInfo{}, err
		}
	}
	return info, nil
}

func validateTarArchive(archivePath string) (archiveTemplateInfo, error) {
	info, err := os.Stat(archivePath)
	if err != nil {
		return archiveTemplateInfo{}, newUsageError("cannot read --archive: %v", err)
	}
	if !info.Mode().IsRegular() {
		return archiveTemplateInfo{}, newUsageError("--archive %s is not a regular file", archivePath)
	}
	if info.Size() > maxStdinBytes {
		return archiveTemplateInfo{}, newUsageError("--archive %s is %d bytes; the limit is %d bytes (32 MiB)", archivePath, info.Size(), int64(maxStdinBytes))
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		return archiveTemplateInfo{}, newUsageError("cannot open --archive: %v", err)
	}
	sum := sha256.Sum256(data)
	reader := io.Reader(bytes.NewReader(data))
	var gzipFile bool
	if strings.HasSuffix(archivePath, ".gz") || strings.HasSuffix(archivePath, ".tgz") {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return archiveTemplateInfo{}, newUsageError("--archive is not valid gzip: %v", err)
		}
		defer func() { _ = gz.Close() }()
		reader = gz
		gzipFile = true
	}
	tr := tar.NewReader(reader)
	seen := map[string]bool{}
	var files int
	var entries int
	var expanded int64
	var memberPaths []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archiveTemplateInfo{}, newUsageError("--archive is not a valid tar archive: %v", err)
		}
		clean, err := validateTarMember(hdr)
		if err != nil {
			return archiveTemplateInfo{}, err
		}
		entries++
		if entries > maxTemplateArchiveMembers {
			return archiveTemplateInfo{}, newUsageError("--archive contains more than %d members", maxTemplateArchiveMembers)
		}
		if hdr.Typeflag == tar.TypeReg {
			files++
			if hdr.Size < 0 {
				return archiveTemplateInfo{}, newUsageError("--archive member %q has invalid size", hdr.Name)
			}
			expanded += hdr.Size
			if expanded > maxTemplateArchiveExpandedBytes {
				return archiveTemplateInfo{}, newUsageError("--archive expands to more than %d bytes", maxTemplateArchiveExpandedBytes)
			}
			if !seen[clean] {
				seen[clean] = true
				memberPaths = append(memberPaths, clean)
			}
		}
	}
	if files == 0 {
		return archiveTemplateInfo{}, newUsageError("--archive must contain at least one regular file")
	}
	sort.Strings(memberPaths)
	return archiveTemplateInfo{Path: archivePath, Gzip: gzipFile, Members: files, MemberPaths: memberPaths, Bytes: info.Size(), Expanded: expanded, SHA256: hex.EncodeToString(sum[:])}, nil
}

func validateTarMember(hdr *tar.Header) (string, error) {
	if hdr == nil {
		return "", newUsageError("--archive contains an invalid tar member")
	}
	name := hdr.Name
	if name == "" || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", newUsageError("--archive contains an invalid member name")
	}
	normalized := strings.TrimSuffix(name, "/")
	clean := path.Clean(normalized)
	if clean == "." || clean == ".." || path.IsAbs(clean) || clean != normalized || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", newUsageError("--archive member %q is not a safe relative path", hdr.Name)
	}
	if clean == ".agentssh-deploy" || strings.HasPrefix(clean, ".agentssh-deploy/") {
		return "", newUsageError("--archive member %q targets reserved AgentSSH deployment artifacts", hdr.Name)
	}
	switch hdr.Typeflag {
	case tar.TypeDir, tar.TypeReg:
		return clean, nil
	default:
		return "", newUsageError("--archive member %q uses unsupported tar type %d; only regular files and directories are accepted", hdr.Name, hdr.Typeflag)
	}
}

func validateComposeFilePath(value string) error {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") || strings.HasPrefix(value, "-") {
		return newUsageError("--compose-file values must be non-empty single-line paths")
	}
	clean := path.Clean(value)
	if path.IsAbs(value) {
		if clean != value || clean == "/" {
			return newUsageError("--compose-file %q must be a clean absolute path or clean path relative to --cwd", value)
		}
		return nil
	}
	if clean == "." || clean == ".." || clean != value || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return newUsageError("--compose-file %q must be a clean path relative to --cwd", value)
	}
	return nil
}

func parseHealthTimeout(value string) (string, error) {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || duration <= 0 {
		return "", newUsageError("--health-timeout requires a positive duration")
	}
	if duration > 30*time.Second {
		return "", newUsageError("--health-timeout must be 30s or less")
	}
	seconds := int(duration.Round(time.Second).Seconds())
	if seconds <= 0 {
		seconds = 1
	}
	return fmt.Sprintf("%d", seconds), nil
}

func validateHealthURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return newUsageError("health URLs must be non-empty single-line URLs")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
		return newUsageError("health URL %q must be http or https with a host and no credentials or fragment", raw)
	}
	return nil
}

func composeDeploymentTemplate(opts planTemplateComposeOptions, archive archiveTemplateInfo) planSpec {
	remoteArchiveName := opts.Revision + ".tar"
	tarFlag := "-xf"
	if archive.Gzip {
		remoteArchiveName += ".gz"
		tarFlag = "-xzf"
	}
	remoteArchive := ".agentssh-deploy/" + remoteArchiveName
	fileBackupPath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".files-before.tar"
	existingListPath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".files-existing.txt"
	missingListPath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".files-missing.txt"
	existingNullListPath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".files-existing.null"
	backupContentsPath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".files-before.contents.txt"
	imagesBeforePath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".images-before.txt"
	psBeforePath := ".agentssh-deploy/" + opts.Revision + "." + opts.Service + ".ps-before.json"
	composeArgs := composeArgv(opts.CWD, opts.ComposeFiles)
	commands := []planCommand{
		{
			ID:        "upload-archive",
			Name:      "Upload validated release archive",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv: []string{"sh", "-c",
				"set -eu; umask 077; mkdir -p .agentssh-deploy; cat > " + shellQuote(remoteArchive),
			},
			CWD:       opts.CWD,
			StdinFile: archive.SidecarPath,
		},
		{
			ID:        "assert-upload-sha256",
			Name:      "Assert uploaded archive SHA-256",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv: []string{"sh", "-c",
				"set -eu; printf '%s  %s\n' " + shellQuote(archive.SHA256) + " " + shellQuote(remoteArchive) + " | sha256sum -c -",
			},
			CWD: opts.CWD,
		},
		{
			ID:        "backup-current-files",
			Name:      "Backup existing files and list new archive paths",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv: []string{"sh", "-c",
				backupCurrentFilesCommand(fileBackupPath, existingListPath, missingListPath, existingNullListPath, backupContentsPath, archive.MemberPaths),
			},
			CWD: opts.CWD,
		},
		{
			ID:        "capture-compose-before",
			Name:      "Capture Compose service evidence before apply",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv: []string{"sh", "-c",
				"set -eu; mkdir -p .agentssh-deploy; " + shellJoin(append(append([]string{"docker", "compose"}, composeArgs...), "images", opts.Service)) + " > " + shellQuote(imagesBeforePath) + "; " + shellJoin(append(append([]string{"docker", "compose"}, composeArgs...), "ps", "--format", "json", opts.Service)) + " > " + shellQuote(psBeforePath),
			},
			CWD: opts.CWD,
		},
		{
			ID:        "apply-archive",
			Name:      "Extract release archive into working tree",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv: []string{"sh", "-c",
				"set -eu; " + assertNoSymlinkPathsCommand(archive.MemberPaths) + "; tar " + tarFlag + " " + shellQuote(remoteArchive) + " -C .",
			},
			CWD: opts.CWD,
		},
		{
			ID:        "build-service",
			Name:      "Build selected Compose service",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv:      append(append([]string{"docker", "compose"}, composeArgs...), "build", opts.Service),
			CWD:       opts.CWD,
		},
		{
			ID:        "up-service",
			Name:      "Start selected Compose service",
			Phase:     executionStepApply,
			OnFailure: executionOnFailureStop,
			Argv:      append(append([]string{"docker", "compose"}, composeArgs...), "up", "-d", opts.Service),
			CWD:       opts.CWD,
		},
		{
			ID:        "collect-compose-ps",
			Name:      "Collect Compose service status evidence",
			Phase:     executionStepVerify,
			OnFailure: executionOnFailureContinue,
			Argv:      append(append([]string{"docker", "compose"}, composeArgs...), "ps", opts.Service),
			CWD:       opts.CWD,
		},
		{
			ID:        "assert-compose-running",
			Name:      "Assert all selected Compose containers are running and healthy when health is configured",
			Phase:     executionStepVerify,
			OnFailure: executionOnFailureContinue,
			Argv: []string{"sh", "-c",
				assertComposeRunningCommand(composeArgs, opts.Service),
			},
			CWD: opts.CWD,
		},
		{
			ID:        "collect-compose-logs",
			Name:      "Collect bounded Compose log evidence",
			Phase:     executionStepVerify,
			OnFailure: executionOnFailureContinue,
			Argv:      append(append([]string{"docker", "compose"}, composeArgs...), "logs", "--tail", "100", "--no-color", opts.Service),
			CWD:       opts.CWD,
		},
	}
	commands = append(commands, healthCheckCommands("verify-local-health", "Verify local health URL", opts.LocalHealthURLs, opts.HealthTimeout, opts.CWD)...)
	commands = append(commands, healthCheckCommands("verify-public-health", "Verify public health URL", opts.PublicHealthURLs, opts.HealthTimeout, opts.CWD)...)
	return planSpec{
		Version: 1,
		Metadata: approval.PlanMetadata{
			Title:       "Compose deployment " + opts.Service + " " + opts.Revision,
			Version:     "1",
			Revision:    opts.Revision,
			Description: fmt.Sprintf("Upload validated archive copy %s (sha256 %s, %d bytes, %d files, %d expanded bytes), apply it under %s, build and start Compose service %s with %s.", archive.SidecarPath, archive.SHA256, archive.Bytes, archive.Members, archive.Expanded, opts.CWD, opts.Service, strings.Join(composeArgv(opts.CWD, opts.ComposeFiles), " ")),
			Impact:      "Builds and restarts only the selected Compose service; Compose may still start declared dependencies.",
			Recovery:    "Use the existing-file backup plus its contents list, the missing-file list of newly introduced paths, before-apply Compose evidence, logs, and health checks to create an explicit corrective plan; an empty backup can be valid for first deploys but is not a rollback by itself.",
		},
		Commands: commands,
	}
}

func backupCurrentFilesCommand(backupPath string, existingPath string, missingPath string, existingNullPath string, contentsPath string, memberPaths []string) string {
	return "set -eu; mkdir -p .agentssh-deploy" +
		"; " + assertNoSymlinkPathsCommand(memberPaths) +
		"; backup=" + shellQuote(backupPath) +
		"; existing=" + shellQuote(existingPath) +
		"; missing=" + shellQuote(missingPath) +
		"; existing_null=" + shellQuote(existingNullPath) +
		"; contents=" + shellQuote(contentsPath) +
		"; : > \"$existing\"; : > \"$missing\"; : > \"$existing_null\"" +
		"; for p in " + shellJoin(memberPaths) + "; do " +
		"if [ -e \"$p\" ]; then " +
		"if [ ! -f \"$p\" ]; then echo \"cannot back up non-regular existing path: $p\" >&2; exit 1; fi; " +
		"if [ ! -r \"$p\" ]; then echo \"cannot read existing path for backup: $p\" >&2; exit 1; fi; " +
		"printf '%s\\n' \"$p\" >> \"$existing\"; printf '%s\\0' \"$p\" >> \"$existing_null\"; " +
		"else printf '%s\\n' \"$p\" >> \"$missing\"; fi; " +
		"done" +
		"; if [ -s \"$existing_null\" ]; then tar -cf \"$backup\" --null --verbatim-files-from -T \"$existing_null\"; tar -tf \"$backup\" > \"$contents\"; else tar -cf \"$backup\" --files-from /dev/null; : > \"$contents\"; fi" +
		"; test -f \"$backup\""
}

func assertNoSymlinkPathsCommand(memberPaths []string) string {
	return "for p in " + shellJoin(memberPaths) + "; do " +
		"check=$p; while :; do " +
		"case \"$check\" in */*) parent=${check%/*};; *) parent=;; esac; " +
		"if [ -z \"$parent\" ] || [ \"$parent\" = \"$check\" ]; then break; fi; " +
		"if [ -L \"$parent\" ]; then echo \"refusing symlink parent path: $parent\" >&2; exit 1; fi; " +
		"check=$parent; " +
		"done; " +
		"if [ -L \"$p\" ]; then echo \"refusing symlink archive path: $p\" >&2; exit 1; fi; " +
		"done"
}

func assertComposeRunningCommand(composeArgs []string, service string) string {
	psCommand := shellJoin(append(append([]string{"docker", "compose"}, composeArgs...), "ps", "-q", "--all", service))
	return "set -eu; ids=$(" + psCommand + ") || exit 1; test -n \"$ids\"; " +
		"for id in $ids; do " +
		"state=$(docker inspect --format '{{.State.Status}}' \"$id\") || exit 1; " +
		"if [ \"$state\" != running ]; then echo \"container $id state is $state\" >&2; exit 1; fi; " +
		"health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \"$id\") || exit 1; " +
		"if [ -n \"$health\" ] && [ \"$health\" != healthy ]; then echo \"container $id health is $health\" >&2; exit 1; fi; " +
		"done"
}

func composeArgv(cwd string, files []string) []string {
	out := make([]string, 0, len(files)*2)
	for _, file := range files {
		clean := path.Clean(file)
		if !path.IsAbs(clean) {
			clean = path.Join(cwd, clean)
		}
		out = append(out, "-f", clean)
	}
	return out
}

func healthCheckCommands(prefix, name string, urls []string, timeout string, cwd string) []planCommand {
	commands := make([]planCommand, 0, len(urls))
	for i, raw := range urls {
		raw = strings.TrimSpace(raw)
		commands = append(commands, planCommand{
			ID:        fmt.Sprintf("%s-%03d", prefix, i+1),
			Name:      name,
			Phase:     executionStepVerify,
			OnFailure: executionOnFailureContinue,
			Argv:      []string{"curl", "-q", "--fail", "--silent", "--show-error", "--max-time", timeout, raw},
			CWD:       cwd,
		})
	}
	return commands
}

func archiveSidecarPath(outputPath string, revision string, sha string, archivePath string) (string, error) {
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return "", err
	}
	ext := ".tar"
	if strings.HasSuffix(archivePath, ".tar.gz") {
		ext = ".tar.gz"
	} else if strings.HasSuffix(archivePath, ".tgz") {
		ext = ".tgz"
	} else if strings.HasSuffix(archivePath, ".gz") {
		ext = ".tar.gz"
	}
	name := filepath.Base(outputPath) + "." + revision + "." + sha[:12] + ext
	return filepath.Join(filepath.Dir(outputAbs), name), nil
}

func copyValidatedArchiveToSidecar(info archiveTemplateInfo) error {
	src, err := os.Open(info.Path)
	if err != nil {
		return newUsageError("cannot open --archive: %v", err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(info.SidecarPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return newUsageError("validated archive copy %s already exists", info.SidecarPath)
		}
		return err
	}
	copyErr := error(nil)
	if _, err := io.Copy(dst, src); err != nil {
		copyErr = err
	}
	if err := dst.Close(); err != nil && copyErr == nil {
		copyErr = err
	}
	if copyErr != nil {
		_ = os.Remove(info.SidecarPath)
		return copyErr
	}
	copied, err := validateTarArchive(info.SidecarPath)
	if err != nil {
		_ = os.Remove(info.SidecarPath)
		return err
	}
	if copied.SHA256 != info.SHA256 {
		_ = os.Remove(info.SidecarPath)
		return newUsageError("--archive changed while creating validated archive copy; rerun template generation")
	}
	return nil
}

func shellJoin(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return newUsageError("--output %s already exists", path)
		}
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Close()
}
