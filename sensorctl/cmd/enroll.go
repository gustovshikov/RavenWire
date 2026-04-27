package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func enrollCmd() *cobra.Command {
	var manager, token, podName, certDir string

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this sensor with a Config Manager",
		Long:  "Generates a local ECDSA keypair, submits the enrollment token, and writes the issued certificate bundle when the manager approves immediately.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if manager == "" {
				return fmt.Errorf("--manager is required")
			}
			if token == "" {
				return fmt.Errorf("--token is required")
			}
			if podName == "" {
				host, err := os.Hostname()
				if err != nil {
					return err
				}
				podName = host
			}
			return runEnroll(manager, token, podName, certDir)
		},
	}

	cmd.Flags().StringVar(&manager, "manager", "", "Config Manager URL, for example https://manager:8443 or http://127.0.0.1:4000/api/v1")
	cmd.Flags().StringVar(&token, "token", "", "One-time enrollment token")
	cmd.Flags().StringVar(&podName, "pod-name", "", "Sensor pod name (defaults to hostname)")
	cmd.Flags().StringVar(&certDir, "cert-dir", envOr("CERT_DIR", "/etc/sensor/certs"), "Directory for sensor.key, sensor.crt, and ca-chain.pem")

	return cmd
}

func runEnroll(manager, token, podName, certDir string) error {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyDER})

	requestBody, err := json.Marshal(map[string]string{
		"token":      token,
		"pod_name":   podName,
		"public_key": string(pubKeyPEM),
	})
	if err != nil {
		return err
	}

	enrollURL := strings.TrimRight(managerAPIBase(manager), "/") + "/enroll"
	resp, err := http.Post(enrollURL, "application/json", bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("POST %s: %w", enrollURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusAccepted:
		fmt.Printf("Enrollment submitted for %s; awaiting operator approval.\n", podName)
		return nil
	case http.StatusOK:
		return writeEnrollmentBundle(resp, privKey, certDir)
	default:
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		return fmt.Errorf("enrollment failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(body.String()))
	}
}

func managerAPIBase(manager string) string {
	manager = strings.TrimRight(manager, "/")
	if strings.HasSuffix(manager, "/api/v1") {
		return manager
	}
	return manager + "/api/v1"
}

func writeEnrollmentBundle(resp *http.Response, privKey *ecdsa.PrivateKey, certDir string) error {
	var certResp struct {
		CertPEM    string `json:"cert_pem"`
		CAChainPEM string `json:"ca_chain_pem"`
		PodID      string `json:"sensor_pod_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("decode enrollment response: %w", err)
	}

	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyDER})

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"sensor.key", privKeyPEM, 0600},
		{"sensor.crt", []byte(certResp.CertPEM), 0644},
		{"ca-chain.pem", []byte(certResp.CAChainPEM), 0644},
	}

	for _, file := range files {
		if err := os.WriteFile(filepath.Join(certDir, file.name), file.data, file.mode); err != nil {
			return fmt.Errorf("write %s: %w", file.name, err)
		}
	}

	fmt.Printf("Enrollment approved for pod %s. Certificate bundle written to %s.\n", certResp.PodID, certDir)
	return nil
}
