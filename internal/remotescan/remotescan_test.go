package remotescan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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

func TestSSHRunner_PerGatewaySSHKeyOverrides(t *testing.T) {
	// Server 1 only accepts key 1
	port1, key1 := startTestSSHServer(t, func(cmd string) (string, int) {
		return "<nmaprun><host><status state=\"up\"/><address addr=\"10.5.5.2\" addrtype=\"ipv4\"/></host></nmaprun>", 0
	})
	// Server 2 only accepts key 2
	port2, key2 := startTestSSHServer(t, func(cmd string) (string, int) {
		return "<nmaprun><host><status state=\"up\"/><address addr=\"10.6.6.2\" addrtype=\"ipv4\"/></host></nmaprun>", 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: "invalid-default-key", // default key won't work on either
		Names:  []string{"openwrt1", "openwrt2"},
		Configs: map[string]config.RemoteScannerConfig{
			"openwrt1": {
				ID:       "openwrt1",
				Host:     "127.0.0.1",
				Port:     port1,
				User:     "root",
				SSHKey:   key1, // per-gateway key 1
				Networks: []string{"10.5.5.0/24"},
			},
			"openwrt2": {
				ID:       "openwrt2",
				Host:     "127.0.0.1",
				Port:     port2,
				User:     "root",
				SSHKey:   key2, // per-gateway key 2
				Networks: []string{"10.6.6.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	out1, err := runner.RunScan(context.Background(), "10.5.5.0/24", []string{"-sn", "10.5.5.0/24"})
	if err != nil {
		t.Fatalf("scan openwrt1 failed: %v", err)
	}
	if !strings.Contains(string(out1), "10.5.5.2") {
		t.Fatalf("scan openwrt1 output = %s", string(out1))
	}

	out2, err := runner.RunScan(context.Background(), "10.6.6.0/24", []string{"-sn", "10.6.6.0/24"})
	if err != nil {
		t.Fatalf("scan openwrt2 failed: %v", err)
	}
	if !strings.Contains(string(out2), "10.6.6.2") {
		t.Fatalf("scan openwrt2 output = %s", string(out2))
	}
}

func TestSSHRunner_DynamicKeyFileReloadOnDiskModification(t *testing.T) {
	// Generate Key 1
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	k1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k1)})
	s1, _ := ssh.NewSignerFromKey(k1)

	// Generate Key 2
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	k2PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k2)})
	s2, _ := ssh.NewSignerFromKey(k2)

	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverSigner, _ := ssh.NewSignerFromKey(serverKey)

	var mu sync.Mutex
	acceptedKey := s1.PublicKey()

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			mu.Lock()
			current := acceptedKey
			mu.Unlock()
			if string(pubKey.Marshal()) == string(current.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	sshConfig.AddHostKey(serverSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var connsMu sync.Mutex
	var activeConns []net.Conn

	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			activeConns = append(activeConns, tcpConn)
			connsMu.Unlock()

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
						_ = newChannel.Reject(ssh.UnknownChannelType, "unknown")
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
								_ = req.Reply(true, nil)
								_, _ = ch.Write([]byte("<nmaprun><host><status state=\"up\"/><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/></host></nmaprun>"))
								exitStatus := struct{ Status uint32 }{0}
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

	// Write Key 1 to disk
	tmpDir := t.TempDir()
	keyFile := fmt.Sprintf("%s/gateway_key", tmpDir)
	if err := os.WriteFile(keyFile, k1PEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.RemoteScannersConfig{
		Enable:     true,
		SSHKeyFile: keyFile,
		Names:      []string{"gw"},
		Configs: map[string]config.RemoteScannerConfig{
			"gw": {
				ID:       "gw",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "root",
				Networks: []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	// 1. Initial scan with Key 1 must succeed
	out1, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("scan with key 1 failed: %v", err)
	}
	if !strings.Contains(string(out1), "10.0.0.1") {
		t.Fatalf("output1 = %s", string(out1))
	}

	// 2. Rotate server accepted key to Key 2 (Key 1 will now be rejected) and close old connections
	mu.Lock()
	acceptedKey = s2.PublicKey()
	mu.Unlock()

	connsMu.Lock()
	for _, c := range activeConns {
		_ = c.Close()
	}
	activeConns = nil
	connsMu.Unlock()

	// Wait briefly so modification time is different
	time.Sleep(20 * time.Millisecond)

	// 3. Overwrite key file on disk with Key 2
	if err := os.WriteFile(keyFile, k2PEM, 0600); err != nil {
		t.Fatal(err)
	}

	// 4. Scan again with the same runner: runner must detect modified keyFile on disk,
	// recycle connection, authenticate with Key 2, and succeed!
	out2, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("scan after key rotation on disk failed: %v", err)
	}
	if !strings.Contains(string(out2), "10.0.0.1") {
		t.Fatalf("output2 = %s", string(out2))
	}
}

func TestSSHRunner_SudoExecution(t *testing.T) {
	var receivedCmds []string
	var mu sync.Mutex

	port, clientKey := startTestSSHServer(t, func(cmd string) (string, int) {
		mu.Lock()
		receivedCmds = append(receivedCmds, cmd)
		mu.Unlock()
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"opnsense", "openwrt"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:       "opnsense",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "opnuser",
				Sudo:     true,
				Networks: []string{"10.0.0.0/24"},
			},
			"openwrt": {
				ID:       "openwrt",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "root",
				Sudo:     false,
				Networks: []string{"10.5.5.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	// 1. Scan target routed via opnsense (Sudo = true)
	_, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("opnsense RunScan: %v", err)
	}

	// 2. Scan target routed via openwrt (Sudo = false)
	_, err = runner.RunScan(context.Background(), "10.5.5.0/24", []string{"-sn", "10.5.5.0/24"})
	if err != nil {
		t.Fatalf("openwrt RunScan: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedCmds) != 2 {
		t.Fatalf("received %d commands, want 2: %v", len(receivedCmds), receivedCmds)
	}

	if !strings.HasPrefix(receivedCmds[0], "sudo -n nmap ") {
		t.Fatalf("expected opnsense command to start with 'sudo -n nmap ', got %q", receivedCmds[0])
	}
	if !strings.HasPrefix(receivedCmds[1], "nmap ") {
		t.Fatalf("expected openwrt command to start with 'nmap ', got %q", receivedCmds[1])
	}
}

func TestSSHRunner_MissingKeyFileReturnsDescriptiveError(t *testing.T) {
	cfg := config.RemoteScannersConfig{
		Enable: true,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:         "opnsense",
				Host:       "127.0.0.1",
				Port:       2222,
				User:       "scanuser",
				SSHKeyFile: "/nonexistent/path/to/key",
				Networks:   []string{"10.0.4.0/24"},
			},
		},
	}
	runner := NewRunner(cfg)
	defer runner.Close()

	_, err := runner.RunScan(context.Background(), "10.0.4.0/24", []string{"-sn", "10.0.4.0/24"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "/nonexistent/path/to/key") {
		t.Fatalf("expected error to mention key file path, got: %v", err)
	}
}

func TestSSHRunner_AuthFailureIncludesUserAndFingerprint(t *testing.T) {
	// Server that rejects all public keys
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("unauthorized")
		},
	}
	sshConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(netConn net.Conn) {
				defer netConn.Close()
				_, _, _, _ = ssh.NewServerConn(netConn, sshConfig)
			}(c)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port

	cfg := config.RemoteScannersConfig{
		Enable: true,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:       "opnsense",
				Host:     "127.0.0.1",
				Port:     port,
				User:     "ipam",
				SSHKey:   string(clientKeyPEM),
				Networks: []string{"10.0.4.0/24"},
			},
		},
	}
	runner := NewRunner(cfg)
	defer runner.Close()

	_, err = runner.RunScan(context.Background(), "10.0.4.0/24", []string{"-sn", "10.0.4.0/24"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, `as user "ipam"`) {
		t.Fatalf("expected error to include 'as user \"ipam\"', got: %v", errMsg)
	}
	if !strings.Contains(errMsg, "SHA256:") {
		t.Fatalf("expected error to include key fingerprint 'SHA256:', got: %v", errMsg)
	}
}
