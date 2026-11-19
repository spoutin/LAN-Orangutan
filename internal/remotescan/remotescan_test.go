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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"golang.org/x/crypto/ssh"
)

// startTestSSHServerWithHostKey creates an in-memory SSH server for testing and
// returns its TCP port, authorized client private key PEM, and server host public key line.
func startTestSSHServerWithHostKey(t *testing.T, handler func(cmd string) (string, int)) (int, string, string) {
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
	hostPubKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

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
	return port, string(clientKeyPEM), hostPubKey
}

// startTestSSHServer creates an in-memory SSH server for testing
func startTestSSHServer(t *testing.T, handler func(cmd string) (string, int)) (int, string) {
	t.Helper()
	port, clientKeyPEM, _ := startTestSSHServerWithHostKey(t, handler)
	return port, clientKeyPEM
}

func TestSSHRunner_SuccessfulRemoteExecution(t *testing.T) {
	expectedXML := `<nmaprun><host><status state="up"/><address addr="10.0.0.15" addrtype="ipv4"/></host></nmaprun>`
	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
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
				ID:         "gateway1",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.0.0.0/24"},
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
	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return "sh: nmap: not found\n", 127
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:         "opnsense",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.0.0.0/24"},
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
	cmdStarted := make(chan struct{})
	releaseServer := make(chan struct{})
	var closeOnce sync.Once
	t.Cleanup(func() {
		closeOnce.Do(func() { close(releaseServer) })
	})

	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		close(cmdStarted)
		<-releaseServer
		return "done", 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"opnsense"},
		Configs: map[string]config.RemoteScannerConfig{
			"opnsense": {
				ID:         "opnsense",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := runner.RunScan(ctx, "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
		errCh <- err
	}()

	<-cmdStarted
	cancel()

	if err := <-errCh; err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	closeOnce.Do(func() { close(releaseServer) })
}

func TestSSHRunner_PerGatewaySSHKeyOverrides(t *testing.T) {
	// Server 1 only accepts key 1
	port1, key1, hostPubKey1 := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return "<nmaprun><host><status state=\"up\"/><address addr=\"10.5.5.2\" addrtype=\"ipv4\"/></host></nmaprun>", 0
	})
	// Server 2 only accepts key 2
	port2, key2, hostPubKey2 := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return "<nmaprun><host><status state=\"up\"/><address addr=\"10.6.6.2\" addrtype=\"ipv4\"/></host></nmaprun>", 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: "invalid-default-key", // default key won't work on either
		Names:  []string{"openwrt1", "openwrt2"},
		Configs: map[string]config.RemoteScannerConfig{
			"openwrt1": {
				ID:         "openwrt1",
				Host:       "127.0.0.1",
				Port:       port1,
				User:       "root",
				SSHKey:     key1, // per-gateway key 1
				SSHHostKey: hostPubKey1,
				Networks:   []string{"10.5.5.0/24"},
			},
			"openwrt2": {
				ID:         "openwrt2",
				Host:       "127.0.0.1",
				Port:       port2,
				User:       "root",
				SSHKey:     key2, // per-gateway key 2
				SSHHostKey: hostPubKey2,
				Networks:   []string{"10.6.6.0/24"},
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
				ID:         "gw",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				SSHHostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(serverSigner.PublicKey()))),
				Networks:   []string{"10.0.0.0/24"},
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

	// 3. Overwrite key file on disk with Key 2 and advance its mtime deterministically
	prevInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, k2PEM, 0600); err != nil {
		t.Fatal(err)
	}
	nextMod := prevInfo.ModTime().Add(time.Second)
	if err := os.Chtimes(keyFile, nextMod, nextMod); err != nil {
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

	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
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
				ID:         "opnsense",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "opnuser",
				Sudo:       true,
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.0.0.0/24"},
			},
			"openwrt": {
				ID:         "openwrt",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				Sudo:       false,
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.5.5.0/24"},
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
				ID:         "opnsense",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "ipam",
				SSHKey:     string(clientKeyPEM),
				SSHHostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
				Networks:   []string{"10.0.4.0/24"},
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

func TestSSHRunner_CanRunPrivileged(t *testing.T) {
	cfg := config.RemoteScannersConfig{
		Enable: true,
		Names:  []string{"sudo-gw", "nonsudo-gw"},
		Configs: map[string]config.RemoteScannerConfig{
			"sudo-gw": {
				ID:       "sudo-gw",
				Networks: []string{"10.1.0.0/24"},
				Sudo:     true,
			},
			"nonsudo-gw": {
				ID:       "nonsudo-gw",
				Networks: []string{"10.2.0.0/24"},
				Sudo:     false,
			},
		},
	}
	runner := NewRunner(cfg)
	defer runner.Close()

	if !runner.CanRunPrivileged("10.1.0.0/24") {
		t.Error("expected 10.1.0.0/24 to be privileged (sudo=true)")
	}
	if runner.CanRunPrivileged("10.2.0.0/24") {
		t.Error("expected 10.2.0.0/24 to be unprivileged (sudo=false)")
	}
	if runner.CanRunPrivileged("192.168.1.0/24") {
		t.Error("expected unconfigured target to be unprivileged")
	}
}

func TestSSHRunner_QuotesShellMetacharactersInArgs(t *testing.T) {
	var receivedCmd string
	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		receivedCmd = cmd
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"gw"},
		Configs: map[string]config.RemoteScannerConfig{
			"gw": {
				ID:         "gw",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				Sudo:       true,
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	args := []string{"-sV", "-p", "80; id", "$(whoami)", "a'b"}
	if _, err := runner.RunScan(context.Background(), "10.0.0.0/24", args); err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	want := `sudo -n nmap '-sV' '-p' '80; id' '$(whoami)' 'a'\''b'`
	if receivedCmd != want {
		t.Fatalf("receivedCmd = %q, want %q", receivedCmd, want)
	}
}

func TestSSHRunner_RejectsNULByteInArgs(t *testing.T) {
	called := false
	port, clientKey := startTestSSHServer(t, func(cmd string) (string, int) {
		called = true
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"gw"},
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

	_, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.1\x00;id"})
	if err == nil {
		t.Fatal("expected error for NUL byte in args, got nil")
	}
	if called {
		t.Fatal("expected SSH command not to execute when args contain NUL byte")
	}
}

func generateOtherAuthorizedKey(t *testing.T) string {
	t.Helper()
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey())))
}

func TestSSHRunner_HostKeyRejectsWhenUnconfigured(t *testing.T) {
	called := false
	port, clientKey, _ := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		called = true
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"gw"},
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

	_, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"})
	if err == nil {
		t.Fatal("expected host key verification error when no known_hosts/ssh_host_key/insecure flag is configured")
	}
	if called {
		t.Fatal("expected remote command not to execute when host key verification is unconfigured")
	}
}

func TestSSHRunner_HostKeyVerifyWithKnownHostsFile(t *testing.T) {
	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return `<nmaprun></nmaprun>`, 0
	})

	khDir := t.TempDir()
	validKH := filepath.Join(khDir, "known_hosts_valid")
	entry := fmt.Sprintf("[127.0.0.1]:%d %s\n", port, hostPubKey)
	if err := os.WriteFile(validKH, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.RemoteScannersConfig{
		Enable:            true,
		SSHKey:            clientKey,
		SSHKnownHostsFile: validKH,
		Names:             []string{"gw"},
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
	if _, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"}); err != nil {
		_ = runner.Close()
		t.Fatalf("expected matching known_hosts to succeed, got: %v", err)
	}
	_ = runner.Close()

	// Mismatched host key in known_hosts must fail
	badKH := filepath.Join(khDir, "known_hosts_bad")
	badEntry := fmt.Sprintf("[127.0.0.1]:%d %s\n", port, generateOtherAuthorizedKey(t))
	if err := os.WriteFile(badKH, []byte(badEntry), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.SSHKnownHostsFile = badKH
	badRunner := NewRunner(cfg)
	defer badRunner.Close()

	if _, err := badRunner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"}); err == nil {
		t.Fatal("expected mismatched known_hosts key to be rejected")
	}
}

func TestSSHRunner_HostKeyVerifyWithPinnedSSHHostKey(t *testing.T) {
	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"gw"},
		Configs: map[string]config.RemoteScannerConfig{
			"gw": {
				ID:         "gw",
				Host:       "127.0.0.1",
				Port:       port,
				User:       "root",
				SSHHostKey: hostPubKey,
				Networks:   []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	if _, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"}); err != nil {
		_ = runner.Close()
		t.Fatalf("expected matching pinned SSHHostKey to succeed, got: %v", err)
	}
	_ = runner.Close()

	sc := cfg.Configs["gw"]
	sc.SSHHostKey = generateOtherAuthorizedKey(t)
	cfg.Configs["gw"] = sc
	badRunner := NewRunner(cfg)
	defer badRunner.Close()

	if _, err := badRunner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"}); err == nil {
		t.Fatal("expected mismatched pinned SSHHostKey to be rejected")
	}
}

func TestSSHRunner_HostKeyVerifyWithInsecureOptIn(t *testing.T) {
	port, clientKey, _ := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable:             true,
		SSHKey:             clientKey,
		SSHInsecureHostKey: true,
		Names:              []string{"gw"},
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

	if _, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"}); err != nil {
		t.Fatalf("expected SSHInsecureHostKey=true to succeed, got: %v", err)
	}
}

func TestSSHRunner_PerGatewayInsecureOverrideFalseRejects(t *testing.T) {
	port, clientKey, _ := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable:             true,
		SSHKey:             clientKey,
		SSHInsecureHostKey: true,
		Names:              []string{"gw"},
		Configs: map[string]config.RemoteScannerConfig{
			"gw": {
				ID:                    "gw",
				Host:                  "127.0.0.1",
				Port:                  port,
				User:                  "root",
				SSHInsecureHostKey:    false,
				SSHInsecureHostKeySet: true,
				Networks:              []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	if _, err := runner.RunScan(context.Background(), "10.0.0.0/24", []string{"-sn", "10.0.0.0/24"}); err == nil {
		t.Fatal("expected per-gateway ssh_insecure_host_key=false to reject unverified host key")
	}
}

func TestSSHRunner_PoolsClientsByUserAndAuth(t *testing.T) {
	var usersMu sync.Mutex
	var users []string

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := ssh.NewSignerFromKey(key)
	hostPubKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	clientKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey1)})
	s1, _ := ssh.NewSignerFromKey(clientKey1)

	clientKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey2)})
	s2, _ := ssh.NewSignerFromKey(clientKey2)

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "alice" && string(pubKey.Marshal()) == string(s1.PublicKey().Marshal()) {
				return nil, nil
			}
			if conn.User() == "bob" && string(pubKey.Marshal()) == string(s2.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unauthorized")
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
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(netConn net.Conn) {
				defer netConn.Close()
				sshConn, chans, reqs, err := ssh.NewServerConn(netConn, sshConfig)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					ch, reqs, err := newChannel.Accept()
					if err != nil {
						return
					}
					go func(channel ssh.Channel, in <-chan *ssh.Request) {
						defer channel.Close()
						for req := range in {
							if req.Type == "exec" {
								usersMu.Lock()
								users = append(users, sshConn.User())
								usersMu.Unlock()
								_ = req.Reply(true, nil)
								_, _ = channel.Write([]byte("<nmaprun></nmaprun>"))
								exitStatus := struct{ Status uint32 }{0}
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatus))
								return
							}
						}
					}(ch, reqs)
				}
			}(c)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	cfg := config.RemoteScannersConfig{
		Enable: true,
		Names:  []string{"gw1", "gw2"},
		Configs: map[string]config.RemoteScannerConfig{
			"gw1": {
				ID: "gw1", Host: "127.0.0.1", Port: port, User: "alice",
				SSHKey: string(key1PEM), SSHHostKey: hostPubKey, Networks: []string{"10.1.0.0/24"},
			},
			"gw2": {
				ID: "gw2", Host: "127.0.0.1", Port: port, User: "bob",
				SSHKey: string(key2PEM), SSHHostKey: hostPubKey, Networks: []string{"10.2.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg).(*SSHRunner)
	defer runner.Close()

	if _, err := runner.RunScan(context.Background(), "10.1.0.0/24", []string{"-sn"}); err != nil {
		t.Fatalf("alice RunScan: %v", err)
	}
	if _, err := runner.RunScan(context.Background(), "10.2.0.0/24", []string{"-sn"}); err != nil {
		t.Fatalf("bob RunScan: %v", err)
	}

	usersMu.Lock()
	defer usersMu.Unlock()
	if len(users) != 2 || users[0] != "alice" || users[1] != "bob" {
		t.Fatalf("expected [alice bob], got %v", users)
	}
	runner.mu.Lock()
	poolLen := len(runner.clients)
	runner.mu.Unlock()
	if poolLen != 2 {
		t.Fatalf("expected 2 distinct pooled clients, got %d", poolLen)
	}
}

func TestSSHRunner_ConcurrentDialDoesNotBlockOtherGatewaysAndHonorsCtx(t *testing.T) {
	// Stalled TCP listener that accepts but never sends SSH banner
	stalledListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalledListener.Close() })
	stalledAccepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := stalledListener.Accept()
			if err != nil {
				return
			}
			select {
			case stalledAccepted <- struct{}{}:
			default:
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	stalledPort := stalledListener.Addr().(*net.TCPAddr).Port

	goodPort, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return `<nmaprun></nmaprun>`, 0
	})

	cfg := config.RemoteScannersConfig{
		Enable: true,
		SSHKey: clientKey,
		Names:  []string{"stalled", "good"},
		Configs: map[string]config.RemoteScannerConfig{
			"stalled": {
				ID: "stalled", Host: "127.0.0.1", Port: stalledPort, User: "root",
				SSHHostKey: hostPubKey, Networks: []string{"10.10.0.0/24"},
			},
			"good": {
				ID: "good", Host: "127.0.0.1", Port: goodPort, User: "root",
				SSHHostKey: hostPubKey, Networks: []string{"10.20.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg)
	defer runner.Close()

	stalledDone := make(chan error, 1)
	ctxStalled, cancelStalled := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelStalled()
	start := time.Now()
	go func() {
		_, err := runner.RunScan(ctxStalled, "10.10.0.0/24", []string{"-sn"})
		stalledDone <- err
	}()

	// Wait until the stalled dial has established TCP and entered SSH handshake;
	// good scan must NOT block behind it.
	<-stalledAccepted
	goodCtx, cancelGood := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelGood()
	if _, err := runner.RunScan(goodCtx, "10.20.0.0/24", []string{"-sn"}); err != nil {
		t.Fatalf("good gateway blocked or failed while stalled gateway dialed: %v", err)
	}

	if err := <-stalledDone; err == nil {
		t.Fatal("expected stalled dial to fail on context timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled dial ignored ctx timeout and took %v", elapsed)
	}
}

func TestSSHRunner_RemoveClientChecksPointerIdentityAndCloseClearsMetadata(t *testing.T) {
	port, clientKey, hostPubKey := startTestSSHServerWithHostKey(t, func(cmd string) (string, int) {
		return `<nmaprun></nmaprun>`, 0
	})
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key")
	if err := os.WriteFile(keyFile, []byte(clientKey), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.RemoteScannersConfig{
		Enable:     true,
		SSHKeyFile: keyFile,
		Names:      []string{"gw"},
		Configs: map[string]config.RemoteScannerConfig{
			"gw": {
				ID: "gw", Host: "127.0.0.1", Port: port, User: "root",
				SSHHostKey: hostPubKey, Networks: []string{"10.0.0.0/24"},
			},
		},
	}

	runner := NewRunner(cfg).(*SSHRunner)
	sc := cfg.Configs["gw"]
	c1, err := runner.getClient(context.Background(), sc)
	if err != nil {
		t.Fatalf("getClient: %v", err)
	}
	key := runner.clientPoolKey(sc)

	// Calling removeClient with a different client pointer must NOT evict c1.
	runner.removeClient(key, &ssh.Client{})
	runner.mu.Lock()
	_, stillPresent := runner.clients[key]
	runner.mu.Unlock()
	if !stillPresent {
		t.Fatal("removeClient evicted live client even though pointer did not match")
	}

	// Removing with the actual pointer removes it.
	runner.removeClient(key, c1)
	runner.mu.Lock()
	_, presentAfter := runner.clients[key]
	runner.mu.Unlock()
	if presentAfter {
		t.Fatal("removeClient did not remove matching client")
	}

	// Re-dial and verify Close clears clients, clientKeyFiles, and clientModTimes.
	if _, err := runner.getClient(context.Background(), sc); err != nil {
		t.Fatalf("re-dial getClient: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.clients) != 0 || len(runner.clientKeyFiles) != 0 || len(runner.clientModTimes) != 0 {
		t.Fatalf("Close did not clear maps: clients=%d keyFiles=%d modTimes=%d", len(runner.clients), len(runner.clientKeyFiles), len(runner.clientModTimes))
	}
}
