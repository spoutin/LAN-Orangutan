package remotescan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"golang.org/x/crypto/ssh"
)

// startTestSSHServer creates an in-memory SSH server for testing
func startTestSSHServer(t *testing.T, handler func(cmd string) (string, int)) (int, string) {
	t.Helper()

	// Generate test server key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	// Generate client key to return to caller
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})
	clientSigner, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if string(pubKey.Marshal()) == string(clientSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sshConn, chans, reqs, err := ssh.NewServerConn(c, sshConfig)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						return
					}
					go func(ch ssh.Channel, in <-chan *ssh.Request) {
						defer ch.Close()
						for req := range in {
							if req.Type == "exec" {
								cmd := string(req.Payload[4:]) // 4-byte string length prefix
								_ = req.Reply(true, nil)
								out, exitCode := handler(cmd)
								_, _ = ch.Write([]byte(out))
								exitStatus := struct{ Status uint32 }{uint32(exitCode)}
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&exitStatus))
								return
							}
						}
					}(channel, requests)
				}
			}(tcpConn)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return port, string(clientKeyPEM)
}

func TestSSHRunner_SuccessfulRemoteExecution(t *testing.T) {
	expectedXML := `<nmaprun><host><status state="up"/><address addr="10.0.0.15" addrtype="ipv4"/></host></nmaprun>`
	port, clientKey := startTestSSHServer(t, func(cmd string) (string, int) {
		if strings.HasPrefix(cmd, "nmap") {
			return expectedXML, 0
		}
		return "unknown command", 1
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"gateway1"},
		Configs: map[string]config.RemoteScannerConfig{
			"gateway1": {
				ID:       "gateway1",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "root",
				Networks: []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	if !runner.HasRemoteScannerForTarget("10.0.0.0/24") {
		t.Fatal("expected remote scanner configured for 10.0.0.0/24")
	}
	if runner.GetGatewayForTarget("10.0.0.0/24") != "gateway1 (127.0.0.1)" {
		t.Fatalf("unexpected gateway name: %s", runner.GetGatewayForTarget("10.0.0.0/24"))
	}

	out, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "-oX", "-", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}
	if string(out) != expectedXML {
		t.Fatalf("got output %q, want %q", string(out), expectedXML)
	}
}

func TestSSHRunner_MissingNmapReturnsTypedError(t *testing.T) {
	port, clientKey := startTestSSHServer(t, func(cmd string) (string, int) {
		return "sh: nmap: not found\n", 127
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:       "opnsense",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "root",
				Networks: []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	_, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	rErr, ok := err.(*RemoteScannerError)
	if !ok {
		t.Fatalf("expected *RemoteScannerError, got %T: %v", err, err)
	}
	if !rErr.IsMissingNmap {
		t.Fatalf("expected IsMissingNmap=true, got false: %v", rErr)
	}
	if rErr.Gateway != "opnsense (127.0.0.1)" {
		t.Fatalf("expected gateway name in error, got: %s", rErr.Gateway)
	}
}

func TestSSHRunner_ContextCancellation(t *testing.T) {
	port, clientKey := startTestSSHServer(t, func(cmd string) (string, int) {
		time.Sleep(2 * time.Second)
		return "done", 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:       "opnsense",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "root",
				Networks: []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := runner.RunScan(ctx, "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
}
