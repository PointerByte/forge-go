// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testInstalledGoVersion = "1.26.0"

func TestNewAppAndExecute(t *testing.T) {
	app := NewApp()
	if app == nil {
		t.Fatal("expected app")
	}
	if app.streams.In == nil || app.streams.Out == nil || app.streams.Err == nil {
		t.Fatal("expected streams to be initialized")
	}
	if app.runner == nil {
		t.Fatal("expected runner to be initialized")
	}

	root := app.rootCommand()
	if root.Use != "qgo" {
		t.Fatalf("expected root use qgo, got %q", root.Use)
	}

	if err := app.runner(t.TempDir(), "version"); err != nil {
		t.Fatalf("expected default runner to execute go version, got %v", err)
	}
}

func TestExecuteRunsRootCommandHelp(t *testing.T) {
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		},
		runner: func(string, ...string) error { return nil },
	}

	root := app.rootCommand()
	root.SetArgs([]string{"help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("expected help execution without error, got %v", err)
	}
}

func TestAppExecute(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: &bytes.Buffer{},
			Err: &bytes.Buffer{},
		},
		runner: func(string, ...string) error { return nil },
	}

	os.Args = []string{"qgo", "help"}
	if err := app.Execute(); err != nil {
		t.Fatalf("expected app.Execute without error, got %v", err)
	}
}

func TestNewCommandCobra(t *testing.T) {
	app := &App{
		streams: IOStreams{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}},
		runner:  func(string, ...string) error { return nil },
	}

	newCmd := newNewCommand(app).Cobra()
	if newCmd.Use != "new" {
		t.Fatalf("expected use new, got %q", newCmd.Use)
	}
	if len(newCmd.Commands()) != 2 {
		t.Fatalf("expected 2 subcommands, got %d", len(newCmd.Commands()))
	}

	serviceCmd := newServiceGeneratorCommand(app, serviceTypeGin).Cobra()
	if serviceCmd.Use != serviceTypeGin {
		t.Fatalf("expected use %s, got %q", serviceTypeGin, serviceCmd.Use)
	}
	if serviceCmd.Flag("module") == nil || serviceCmd.Flag("app-name") == nil || serviceCmd.Flag("config-format") == nil || serviceCmd.Flag("go-version") == nil || serviceCmd.Flag("dir") == nil {
		t.Fatal("expected scaffold flags to be registered")
	}
}

func TestServiceCommandRunE(t *testing.T) {
	output := &bytes.Buffer{}
	runnerCalls := []string{}
	app := &App{
		streams: IOStreams{
			In:  strings.NewReader(""),
			Out: output,
			Err: &bytes.Buffer{},
		},
		runner: func(_ string, args ...string) error {
			runnerCalls = append(runnerCalls, strings.Join(args, " "))
			return nil
		},
		goVersionResolver: func() (string, error) { return "go" + testInstalledGoVersion, nil },
	}

	cmd := app.rootCommand()
	dir := filepath.Join(t.TempDir(), "testsvc")
	cmd.SetArgs([]string{
		"new", "gin",
		"--module", "github.com/acme/testsvc",
		"--app-name", "testsvc",
		"--config-format", "yaml",
		"--dir", dir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command execution without error, got %v", err)
	}
	if !strings.Contains(output.String(), "Service created in") {
		t.Fatalf("expected success output, got %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "resources", "application.yaml")); err != nil {
		t.Fatalf("expected resources/application.yaml to be generated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cmd", "main.go")); err != nil {
		t.Fatalf("expected cmd/main.go to be generated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected main.go not to be generated at project root, got %v", err)
	}
	if !containsString(runnerCalls, "mod edit -go="+testInstalledGoVersion) {
		t.Fatalf("expected go mod edit call with installed Go version, got %#v", runnerCalls)
	}
}

func TestResolveScaffoldOptionsErrors(t *testing.T) {
	streams := IOStreams{In: strings.NewReader("\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if _, err := resolveScaffoldOptions(streams, &scaffoldOptions{}, testInstalledGoVersion); err == nil {
		t.Fatal("expected missing module error")
	}

	streams = IOStreams{In: strings.NewReader("github.com/acme/orders\n\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if _, err := resolveScaffoldOptions(streams, &scaffoldOptions{}, testInstalledGoVersion); err == nil {
		t.Fatal("expected missing app.name error")
	}

	streams = IOStreams{In: strings.NewReader("github.com/acme/orders\norders\nxml\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if _, err := resolveScaffoldOptions(streams, &scaffoldOptions{}, testInstalledGoVersion); err == nil {
		t.Fatal("expected invalid config format error")
	}

	streams = IOStreams{In: strings.NewReader("github.com/acme/order s\norders\nyaml\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if _, err := resolveScaffoldOptions(streams, &scaffoldOptions{}, testInstalledGoVersion); err == nil || !strings.Contains(err.Error(), "package/module name contains invalid characters") {
		t.Fatalf("expected invalid module path error, got %v", err)
	}

	streams = IOStreams{In: strings.NewReader("github.com/acme/orders\norders api\nyaml\n"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if _, err := resolveScaffoldOptions(streams, &scaffoldOptions{}, testInstalledGoVersion); err == nil || !strings.Contains(err.Error(), "app.name contains invalid characters") {
		t.Fatalf("expected invalid app.name error, got %v", err)
	}

	streams = IOStreams{
		In:  strings.NewReader(""),
		Out: &bytes.Buffer{},
		Err: &bytes.Buffer{},
	}
	if _, err := resolveScaffoldOptions(streams, &scaffoldOptions{
		modulePath:   "github.com/acme/orders",
		appName:      "orders-api",
		configFormat: "yaml",
		outputDir:    filepath.Join("tmp", "orders api"),
	}, testInstalledGoVersion); err != nil {
		t.Fatalf("expected explicit output dir to be accepted, got %v", err)
	}
}

func TestResolveScaffoldOptionsUsesAppNameAsDefaultDir(t *testing.T) {
	streams := IOStreams{
		In:  strings.NewReader("github.com/acme/orders\norders-service\n\n"),
		Out: &bytes.Buffer{},
		Err: &bytes.Buffer{},
	}

	options, err := resolveScaffoldOptions(streams, &scaffoldOptions{}, testInstalledGoVersion)
	if err != nil {
		t.Fatalf("resolveScaffoldOptions returned error: %v", err)
	}

	if options.outputDir != "orders-service" {
		t.Fatalf("expected derived output dir orders-service, got %q", options.outputDir)
	}
	if options.goVersion != testInstalledGoVersion {
		t.Fatalf("expected default Go version %q, got %q", testInstalledGoVersion, options.goVersion)
	}
}

func TestPromptRequiredBranches(t *testing.T) {
	if value, err := promptRequired(nil, &bytes.Buffer{}, "label", " fallback "); err != nil || value != "fallback" {
		t.Fatalf("expected fallback value, got value=%q err=%v", value, err)
	}

	reader := strings.NewReader("value\n")
	if value, err := promptRequired(bufioReader(reader), &bytes.Buffer{}, "label", ""); err != nil || value != "value" {
		t.Fatalf("expected read value, got value=%q err=%v", value, err)
	}

	if _, err := promptRequired(bufioReader(strings.NewReader("value\n")), errorWriter{}, "label", ""); err == nil {
		t.Fatal("expected writer error")
	}

	if _, err := promptRequired(bufioReader(errorReader{}), &bytes.Buffer{}, "label", ""); err == nil {
		t.Fatal("expected reader error")
	}
}

func TestPromptConfigFormatBranches(t *testing.T) {
	if value, err := promptConfigFormat(bufioReader(strings.NewReader("")), &bytes.Buffer{}, "json"); err != nil || value != configJSON {
		t.Fatalf("expected json fallback, got value=%q err=%v", value, err)
	}

	if _, err := promptConfigFormat(bufioReader(strings.NewReader("")), &bytes.Buffer{}, "xml"); err == nil {
		t.Fatal("expected invalid fallback format error")
	}

	if value, err := promptConfigFormat(bufioReader(strings.NewReader("\n")), &bytes.Buffer{}, ""); err != nil || value != configYAML {
		t.Fatalf("expected default yaml, got value=%q err=%v", value, err)
	}

	if _, err := promptConfigFormat(bufioReader(strings.NewReader("toml\n")), &bytes.Buffer{}, ""); err == nil {
		t.Fatal("expected invalid input format error")
	}

	if !isValidConfigFormat(configYAML) || !isValidConfigFormat(configJSON) || isValidConfigFormat("xml") {
		t.Fatal("unexpected config format validation result")
	}

	if !isValidModulePath("github.com/acme/orders") || isValidModulePath("github.com/acme/order s") || isValidModulePath("github.com/acme/orders!") {
		t.Fatal("unexpected module path validation result")
	}

	if !isValidServiceName("orders-api") || !isValidServiceName("orders_api") || isValidServiceName("orders api") || isValidServiceName("orders!") {
		t.Fatal("unexpected service name validation result")
	}

	if _, err := promptConfigFormat(bufioReader(strings.NewReader("yaml\n")), errorWriter{}, ""); err == nil {
		t.Fatal("expected writer error")
	}

	if _, err := promptConfigFormat(bufioReader(errorReader{}), &bytes.Buffer{}, ""); err == nil {
		t.Fatal("expected reader error")
	}
}

func TestPromptGoVersionBranches(t *testing.T) {
	if value, err := promptGoVersion(nil, &bytes.Buffer{}, " go1.25.1 ", testInstalledGoVersion); err != nil || value != "1.25.1" {
		t.Fatalf("expected normalized fallback Go version, got value=%q err=%v", value, err)
	}

	if _, err := promptGoVersion(nil, &bytes.Buffer{}, "1.x", testInstalledGoVersion); err == nil {
		t.Fatal("expected invalid fallback Go version error")
	}

	if value, err := promptGoVersion(bufioReader(strings.NewReader("\n")), &bytes.Buffer{}, "", "go"+testInstalledGoVersion); err != nil || value != testInstalledGoVersion {
		t.Fatalf("expected default Go version, got value=%q err=%v", value, err)
	}

	if value, err := promptGoVersion(bufioReader(strings.NewReader("go1.24\n")), &bytes.Buffer{}, "", testInstalledGoVersion); err != nil || value != "1.24" {
		t.Fatalf("expected normalized input Go version, got value=%q err=%v", value, err)
	}

	if _, err := promptGoVersion(bufioReader(strings.NewReader("latest\n")), &bytes.Buffer{}, "", testInstalledGoVersion); err == nil {
		t.Fatal("expected invalid input Go version error")
	}

	if _, err := promptGoVersion(bufioReader(strings.NewReader("\n")), &bytes.Buffer{}, "", "latest"); err == nil {
		t.Fatal("expected invalid default Go version error")
	}

	if !isValidGoVersion("1.26") || !isValidGoVersion("1.26.0") || isValidGoVersion("go1.26.0") || isValidGoVersion("latest") {
		t.Fatal("unexpected Go version validation result")
	}

	if _, err := promptGoVersion(bufioReader(strings.NewReader("1.26\n")), errorWriter{}, "", testInstalledGoVersion); err == nil {
		t.Fatal("expected writer error")
	}

	if _, err := promptGoVersion(bufioReader(errorReader{}), &bytes.Buffer{}, "", testInstalledGoVersion); err == nil {
		t.Fatal("expected reader error")
	}
}

func TestCreateServiceErrorBranches(t *testing.T) {
	streams := IOStreams{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}

	t.Run("abs error", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return nil })
		sc.absFn = func(string) (string, error) { return "", errors.New("abs") }
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: "svc", configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "resolve output directory") {
			t.Fatalf("expected abs error, got %v", err)
		}
	})

	t.Run("existing directory", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return nil })
		dir := t.TempDir()
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: dir, configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "output directory already exists") {
			t.Fatalf("expected existing dir error, got %v", err)
		}
	})

	t.Run("stat error", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return nil })
		sc.absFn = func(value string) (string, error) { return value, nil }
		sc.statFn = func(string) (os.FileInfo, error) { return nil, errors.New("stat") }
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: "svc", configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "inspect output directory") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return nil })
		sc.absFn = func(value string) (string, error) { return value, nil }
		sc.statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		sc.mkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir") }
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: "svc", configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "create output directory") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("unsupported format", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return nil })
		sc.absFn = func(value string) (string, error) { return value, nil }
		sc.statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		sc.mkdirAllFn = func(string, os.FileMode) error { return nil }
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: "svc", configFormat: "xml", appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "unsupported config format") {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})

	t.Run("write file error", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return nil })
		sc.absFn = func(value string) (string, error) { return value, nil }
		sc.statFn = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		sc.mkdirAllFn = func(string, os.FileMode) error { return nil }
		sc.writeFileFn = func(string, []byte, os.FileMode) error { return errors.New("write") }
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: "svc", configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "write ") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("mod init error", func(t *testing.T) {
		sc := newScaffolder(streams, func(string, ...string) error { return errors.New("init") })
		dir := filepath.Join(t.TempDir(), "svc")
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: dir, configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "initialize go module") {
			t.Fatalf("expected mod init error, got %v", err)
		}
	})

	t.Run("mod edit error", func(t *testing.T) {
		sc := newScaffolder(streams, func(_ string, args ...string) error {
			if len(args) >= 3 && args[0] == "mod" && args[1] == "edit" {
				return errors.New("edit")
			}
			return nil
		})
		dir := filepath.Join(t.TempDir(), "svc")
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: dir, configFormat: configYAML, goVersion: testInstalledGoVersion, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "set Go version") {
			t.Fatalf("expected mod edit error, got %v", err)
		}
	})

	t.Run("mod tidy error", func(t *testing.T) {
		callCount := 0
		sc := newScaffolder(streams, func(string, ...string) error {
			callCount++
			if callCount == 3 {
				return errors.New("tidy")
			}
			return nil
		})
		dir := filepath.Join(t.TempDir(), "svc")
		err := sc.createService(serviceTypeGin, scaffoldOptions{outputDir: dir, configFormat: configYAML, appName: "svc", modulePath: "github.com/acme/svc"})
		if err == nil || !strings.Contains(err.Error(), "install dependencies") {
			t.Fatalf("expected mod tidy error, got %v", err)
		}
	})
}

func TestTemplateBranches(t *testing.T) {
	if got := buildMainTemplate(serviceTypeGRPC, "app"); !strings.Contains(got, "serverGRPC.NewIConfig(nil, nil)") {
		t.Fatalf("expected grpc main template, got %q", got)
	}

	if got := buildMainTemplate("unknown", "app"); got != "" {
		t.Fatalf("expected empty main template for unknown type, got %q", got)
	}

	if !strings.Contains(buildApplicationYAML(serviceTypeGRPC, "grpc-app"), "port: \":50051\"") {
		t.Fatal("expected grpc yaml template")
	}
	if !strings.Contains(buildApplicationYAML(serviceTypeGRPC, "grpc-app"), "rate:\n      limit: 1000\n      burst: 2000") {
		t.Fatal("expected grpc yaml template to include rate config")
	}
	if !strings.Contains(buildApplicationYAML(serviceTypeGRPC, "grpc-app"), "SkipFunction: []") {
		t.Fatal("expected grpc yaml template to include empty SkipFunction")
	}
	ginYAML := buildApplicationYAML(serviceTypeGin, "gin-app")
	if !strings.Contains(ginYAML, "transport: header") {
		t.Fatal("expected gin yaml template")
	}
	if !strings.Contains(ginYAML, "  gin:\n    groups:\n      - /api/v1") {
		t.Fatal("expected gin yaml template to include server.gin.groups")
	}
	if strings.Contains(ginYAML, "server:\n  groups:") {
		t.Fatal("expected gin yaml template not to include legacy server.groups")
	}
	if !strings.Contains(ginYAML, "private_key: ./certs/jwt/ed25519-key.pem") {
		t.Fatal("expected gin yaml template to include Ed25519 jwt key path")
	}
	if !strings.Contains(ginYAML, "client:\n  http:") {
		t.Fatal("expected gin yaml template to include client.http")
	}
	if !strings.Contains(ginYAML, "certFile: ./certs/server/cert.pem") {
		t.Fatal("expected gin yaml template to include server gin tls cert path")
	}

	grpcJSON, err := buildApplicationJSON(serviceTypeGRPC, "grpc-app")
	if err != nil || !strings.Contains(grpcJSON, "\"port\": \":50051\"") {
		t.Fatalf("expected grpc json template, got err=%v", err)
	}
	if !strings.Contains(grpcJSON, "\"SkipFunction\": []") {
		t.Fatal("expected grpc json template to include empty SkipFunction")
	}
	var grpcJSONData map[string]any
	if err := json.Unmarshal([]byte(grpcJSON), &grpcJSONData); err != nil {
		t.Fatalf("expected valid grpc json template: %v", err)
	}
	grpcServerConfig := grpcJSONData["server"].(map[string]any)["grpc"].(map[string]any)
	rateConfig := grpcServerConfig["rate"].(map[string]any)
	if rateConfig["limit"] != float64(1000) || rateConfig["burst"] != float64(2000) {
		t.Fatalf("expected grpc json template to include rate config, got %#v", rateConfig)
	}

	ginJSON, err := buildApplicationJSON(serviceTypeGin, "gin-app")
	if err != nil || !strings.Contains(ginJSON, "\"transport\": \"header\"") {
		t.Fatalf("expected gin json template, got err=%v", err)
	}
	if !strings.Contains(ginJSON, "\"private_key\": \"./certs/jwt/ed25519-key.pem\"") {
		t.Fatal("expected gin json template to include Ed25519 jwt key path")
	}
	if !strings.Contains(ginJSON, "\"http\"") {
		t.Fatal("expected gin json template to include client.http")
	}
	var ginJSONData map[string]any
	if err := json.Unmarshal([]byte(ginJSON), &ginJSONData); err != nil {
		t.Fatalf("expected valid gin json template: %v", err)
	}
	serverConfig := ginJSONData["server"].(map[string]any)
	ginConfig := serverConfig["gin"].(map[string]any)
	groups := ginConfig["groups"].([]any)
	if len(groups) != 1 || groups[0] != "/api/v1" {
		t.Fatalf("expected gin json template to include server.gin.groups, got %#v", groups)
	}
	if _, ok := serverConfig["groups"]; ok {
		t.Fatal("expected gin json template not to include legacy server.groups")
	}
	if strings.Contains(ginJSON, "\"gin\": {\n    \"autotls\"") {
		t.Fatal("expected gin json template not to use top-level gin.autotls")
	}

	if _, err := buildProjectFiles(serviceTypeGin, scaffoldOptions{appName: "svc", configFormat: "xml"}); err == nil {
		t.Fatal("expected buildProjectFiles unsupported format error")
	}

	files, err := buildProjectFiles(serviceTypeGRPC, scaffoldOptions{appName: "svc", configFormat: configYAML})
	if err != nil {
		t.Fatalf("expected grpc yaml files, got %v", err)
	}
	if !strings.Contains(files["resources/application.yaml"], "port: \":50051\"") {
		t.Fatal("expected grpc application yaml file")
	}
	if !strings.Contains(files[generatedMainPath], "serverGRPC.NewIConfig(nil, nil)") {
		t.Fatal("expected grpc main file under cmd")
	}
	if _, ok := files["main.go"]; ok {
		t.Fatal("expected main.go under cmd directory")
	}
	if _, ok := files["application.yaml"]; ok {
		t.Fatal("expected application yaml under resources")
	}
}

func bufioReader(reader io.Reader) *bufio.Reader {
	return bufio.NewReader(reader)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write")
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
