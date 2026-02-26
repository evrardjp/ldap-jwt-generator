package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewTokenIssuer(t *testing.T) {
	// Generate test keys for successful test cases
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Invalid PEM content for error testing
	invalidPEM := []byte("not a valid PEM")

	tests := []struct {
		name           string
		tokenLifetime  string
		jwtIssuerFQDN  string
		setupFiles     func(t *testing.T) (privateKeyPath, publicKeyPath string)
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, ti *TokenIssuer)
	}{
		{
			name:          "missing JWT_ISSUER_FQDN",
			tokenLifetime: "4h",
			jwtIssuerFQDN: "",
			setupFiles: func(t *testing.T) (string, string) {
				return "", ""
			},
			wantErr:     true,
			errContains: "JWT_ISSUER_FQDN environment variable is required",
		},
		{
			name:          "invalid TOKEN_LIFETIME duration",
			tokenLifetime: "invalid-duration",
			jwtIssuerFQDN: "test.example.com",
			setupFiles: func(t *testing.T) (string, string) {
				return "", ""
			},
			wantErr:     true,
			errContains: "unable to parse duration",
		},
		{
			name:          "missing private key file",
			tokenLifetime: "4h",
			jwtIssuerFQDN: "test.example.com",
			setupFiles: func(t *testing.T) (string, string) {
				// Return paths to non-existent files
				tmpDir := t.TempDir()
				privateKeyPath := filepath.Join(tmpDir, "private.pem")
				publicKeyPath := filepath.Join(tmpDir, "public.pem")
				return privateKeyPath, publicKeyPath
			},
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:          "missing public key file",
			tokenLifetime: "4h",
			jwtIssuerFQDN: "test.example.com",
			setupFiles: func(t *testing.T) (string, string) {
				// Create only private key, not public key
				tmpDir := t.TempDir()
				privateKeyPath := filepath.Join(tmpDir, "private.pem")
				publicKeyPath := filepath.Join(tmpDir, "public.pem")
				if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
					t.Fatalf("Failed to write private key: %v", err)
				}
				return privateKeyPath, publicKeyPath
			},
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:          "invalid private key PEM content",
			tokenLifetime: "4h",
			jwtIssuerFQDN: "test.example.com",
			setupFiles: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				privateKeyPath := filepath.Join(tmpDir, "private.pem")
				publicKeyPath := filepath.Join(tmpDir, "public.pem")
				if err := os.WriteFile(privateKeyPath, invalidPEM, 0600); err != nil {
					t.Fatalf("Failed to write private key: %v", err)
				}
				if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
					t.Fatalf("Failed to write public key: %v", err)
				}
				return privateKeyPath, publicKeyPath
			},
			wantErr:     true,
			errContains: "unable to parse ECDSA private key",
		},
		{
			name:          "invalid public key PEM content",
			tokenLifetime: "4h",
			jwtIssuerFQDN: "test.example.com",
			setupFiles: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				privateKeyPath := filepath.Join(tmpDir, "private.pem")
				publicKeyPath := filepath.Join(tmpDir, "public.pem")
				if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
					t.Fatalf("Failed to write private key: %v", err)
				}
				if err := os.WriteFile(publicKeyPath, invalidPEM, 0644); err != nil {
					t.Fatalf("Failed to write public key: %v", err)
				}
				return privateKeyPath, publicKeyPath
			},
			wantErr:     true,
			errContains: "unable to parse ECDSA public key",
		},
		{
			name:          "successful initialization with default duration",
			tokenLifetime: "", // Should default to 4h
			jwtIssuerFQDN: "test.example.com",
			setupFiles: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				privateKeyPath := filepath.Join(tmpDir, "private.pem")
				publicKeyPath := filepath.Join(tmpDir, "public.pem")
				if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
					t.Fatalf("Failed to write private key: %v", err)
				}
				if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
					t.Fatalf("Failed to write public key: %v", err)
				}
				return privateKeyPath, publicKeyPath
			},
			wantErr: false,
			validateResult: func(t *testing.T, ti *TokenIssuer) {
				if ti == nil {
					t.Fatal("Expected non-nil TokenIssuer")
				}
				if ti.TokenDuration != 4*time.Hour {
					t.Errorf("Expected default duration of 4h, got %v", ti.TokenDuration)
				}
				if ti.IssuerFQDN != "test.example.com" {
					t.Errorf("Expected IssuerFQDN 'test.example.com', got %s", ti.IssuerFQDN)
				}
				if ti.PrivateKey == nil {
					t.Error("Expected non-nil PrivateKey")
				}
				if ti.PublicKey == nil {
					t.Error("Expected non-nil PublicKey")
				}
			},
		},
		{
			name:          "successful initialization with custom duration",
			tokenLifetime: "2h30m",
			jwtIssuerFQDN: "auth.example.org",
			setupFiles: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				privateKeyPath := filepath.Join(tmpDir, "private.pem")
				publicKeyPath := filepath.Join(tmpDir, "public.pem")
				if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
					t.Fatalf("Failed to write private key: %v", err)
				}
				if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
					t.Fatalf("Failed to write public key: %v", err)
				}
				return privateKeyPath, publicKeyPath
			},
			wantErr: false,
			validateResult: func(t *testing.T, ti *TokenIssuer) {
				if ti == nil {
					t.Fatal("Expected non-nil TokenIssuer")
				}
				expectedDuration := 2*time.Hour + 30*time.Minute
				if ti.TokenDuration != expectedDuration {
					t.Errorf("Expected duration of %v, got %v", expectedDuration, ti.TokenDuration)
				}
				if ti.IssuerFQDN != "auth.example.org" {
					t.Errorf("Expected IssuerFQDN 'auth.example.org', got %s", ti.IssuerFQDN)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			if tt.tokenLifetime != "" {
				t.Setenv("TOKEN_LIFETIME", tt.tokenLifetime)
			}
			if tt.jwtIssuerFQDN != "" {
				t.Setenv("JWT_ISSUER_FQDN", tt.jwtIssuerFQDN)
			}

			// Set up files
			privateKeyPath, publicKeyPath := tt.setupFiles(t)

			// Call the function
			got, err := newTokenIssuer(privateKeyPath, publicKeyPath)

			// Check error expectation
			if tt.wantErr {
				if err == nil {
					t.Errorf("newTokenIssuer() expected error containing '%s', got nil", tt.errContains)
					return
				}
				// TODO: Improve error handling/wrapping to check error, instead of string match. This is just quick and dirty.
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("newTokenIssuer() error = %v, expected error containing '%s'", err, tt.errContains)
				}
				return
			}

			// No error expected
			if err != nil {
				t.Errorf("newTokenIssuer() unexpected error = %v", err)
				return
			}

			// Validate result
			if tt.validateResult != nil {
				tt.validateResult(t, got)
			}
		})
	}
}
