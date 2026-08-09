// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package awskms

import (
	"context"
	"errors"
	"testing"

	"github.com/PointerByte/forge-go/encrypt/common"
	sdkaws "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/spf13/viper"
)

func TestLoadAWSConfig(t *testing.T) {
	previous := loadDefaultAWSConfigFn
	t.Cleanup(func() { loadDefaultAWSConfigFn = previous })

	t.Run("success appends otel middlewares", func(t *testing.T) {
		loadDefaultAWSConfigFn = func(context.Context, ...func(*awsconfig.LoadOptions) error) (sdkaws.Config, error) {
			return sdkaws.Config{}, nil
		}
		if _, err := loadAWSConfig(context.Background()); err != nil {
			t.Fatalf("loadAWSConfig() error = %v", err)
		}
	})

	t.Run("load error is propagated", func(t *testing.T) {
		loadDefaultAWSConfigFn = func(context.Context, ...func(*awsconfig.LoadOptions) error) (sdkaws.Config, error) {
			return sdkaws.Config{}, errors.New("load boom")
		}
		if _, err := loadAWSConfig(context.Background()); err == nil {
			t.Fatal("expected loadAWSConfig() error")
		}
	})
}

func TestToAWSECCKeySpec(t *testing.T) {
	tests := []struct {
		name    string
		curve   common.CurveAsymmetricKey
		want    types.KeySpec
		wantErr bool
	}{
		{name: "P256", curve: common.CurveP256, want: types.KeySpecEccNistP256},
		{name: "P384", curve: common.CurveP384, want: types.KeySpecEccNistP384},
		{name: "P521", curve: common.CurveP521, want: types.KeySpecEccNistP521},
		{name: "unsupported", curve: common.CurveAsymmetricKey(99), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := toAWSECCKeySpec(test.curve)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("toAWSECCKeySpec() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("toAWSECCKeySpec() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestLooksLikeAWSKMSKeyReference(t *testing.T) {
	t.Cleanup(viper.Reset)

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "arn", key: "arn:aws:kms:us-east-1:111122223333:key/abcd", want: true},
		{name: "alias", key: "alias/my-key", want: true},
		{name: "multi-region key", key: "mrk-1234", want: true},
		{name: "uuid-like", key: "1234-5678-9012-3456-7890", want: true},
		{name: "plain name", key: "plain", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := looksLikeAWSKMSKeyReference(test.key); got != test.want {
				t.Fatalf("looksLikeAWSKMSKeyReference(%q) = %v, want %v", test.key, got, test.want)
			}
		})
	}

	t.Run("empty falls back to configured arn", func(t *testing.T) {
		viper.Reset()
		if looksLikeAWSKMSKeyReference("") {
			t.Fatal("expected false when no ARN configured")
		}
		viper.Set(defaultKMSARNKey, "arn:aws:kms:us-east-1:111122223333:key/abcd")
		if !looksLikeAWSKMSKeyReference("") {
			t.Fatal("expected true when ARN configured")
		}
	})
}
