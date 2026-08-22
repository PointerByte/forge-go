// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import "testing"

var benchmarkProjectFiles map[string]string

func BenchmarkBuildProjectFiles(b *testing.B) {
	benchmarks := []struct {
		name         string
		serviceType  string
		configFormat string
	}{
		{name: "GinYAML", serviceType: serviceTypeGin, configFormat: configYAML},
		{name: "GinJSON", serviceType: serviceTypeGin, configFormat: configJSON},
		{name: "GRPCYAML", serviceType: serviceTypeGRPC, configFormat: configYAML},
		{name: "GRPCJSON", serviceType: serviceTypeGRPC, configFormat: configJSON},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			options := scaffoldOptions{
				modulePath:   "example.invalid/benchmark/service",
				appName:      "benchmark-service",
				configFormat: benchmark.configFormat,
				goVersion:    "1.25.0",
				outputDir:    "benchmark-service",
			}

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				files, err := buildProjectFiles(benchmark.serviceType, options)
				if err != nil {
					b.Fatalf("buildProjectFiles() error = %v", err)
				}
				benchmarkProjectFiles = files
			}
		})
	}
}
