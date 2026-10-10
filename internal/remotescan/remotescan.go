package remotescan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"golang.org/x/crypto/ssh"
)

// Runner manages remote scanner dispatch and execution over SSH
type Runner interface {
	HasRemoteScannerForTarget(target string) bool
	GetGatewayForTarget(target string) string
	RunScan(ctx context.Context, target string, args []string) ([]byte, error)
	Close() error
}

// RemoteScannerError describes a failure executing on a remote edge gateway
type RemoteScannerError struct {
	Gateway       string
	Target        string
	Err           error
	IsMissingNmap bool
}

func (e *RemoteScannerError) Error() string {
	if e.IsMissingNmap {
		return fmt.Sprintf("remote scanner %s: nmap executable not found (or missing libraries): %v", e.Gateway, e.Err)
	}
	return fmt.Sprintf("remote scanner %s failed for %s: %v", e.Gateway, e.Target, e.Err)
}

func (e *RemoteScannerError) Unwrap() error {
	return e.Err
}

// SSHRunner implements Runner using SSH connections
type SSHRunner struct {
	cfg            config.RemoteScannersConfig
	clients        map[string]*ssh.Client
	clientKeyFiles map[string]string
	clientModTimes map[string]time.Time
	mu             sync.Mutex
}

func parsePrivateKeyFromFile(path string) (ssh.Signer, time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	return signer, fi.ModTime(), nil
}

// NewRunner creates a new SSHRunner from configuration
func NewRunner(cfg config.RemoteScannersConfig) Runner {
	return &SSHRunner{
		cfg:            cfg,
		clients:        make(map[string]*ssh.Client),
		clientKeyFiles: make(map[string]string),
		clientModTimes: make(map[string]time.Time),
	}
}

func (r *SSHRunner) findScannerConfig(target string) (*config.RemoteScannerConfig, bool) {
	if !r.cfg.Enable {
		return nil, false
	}
	// Try CIDR lookup first
	if sc, ok := r.cfg.FindScannerForCIDR(target); ok {
		return sc, true
	}
	// Try IP lookup
	if sc, ok := r.cfg.FindScannerForIP(target); ok {
		return sc, true
	}
	return nil, false
}

// HasRemoteScannerForTarget reports whether target is configured to be scanned via a remote gateway
func (r *SSHRunner) HasRemoteScannerForTarget(target string) bool {
	_, ok := r.findScannerConfig(target)
	return ok
}

// GetGatewayForTarget returns human-readable name of the gateway assigned to target
func (r *SSHRunner) GetGatewayForTarget(target string) string {
	sc, ok := r.findScannerConfig(target)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s (%s)", sc.ID, sc.Host)
}

func (r *SSHRunner) getKeyFileForScanner(sc config.RemoteScannerConfig) string {
	if sc.SSHKeyFile != "" {
		return sc.SSHKeyFile
	}
	return r.cfg.SSHKeyFile
}

func (r *SSHRunner) getAuthMethods(sc config.RemoteScannerConfig) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	// 1. Gateway-specific credentials
	if sc.SSHKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(sc.SSHKey)); err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	} else if sc.SSHKeyFile != "" {
		if signer, _, err := parsePrivateKeyFromFile(sc.SSHKeyFile); err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}

	if sc.SSHPassword != "" {
		methods = append(methods, ssh.Password(sc.SSHPassword))
	}

	if len(methods) > 0 {
		return methods
	}

	// 2. Fallback to top-level shared credentials
	if r.cfg.SSHKey != "" {
		if signer, err := ssh.ParsePrivateKey([]byte(r.cfg.SSHKey)); err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	} else if r.cfg.SSHKeyFile != "" {
		if signer, _, err := parsePrivateKeyFromFile(r.cfg.SSHKeyFile); err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}

	if r.cfg.SSHPassword != "" {
		methods = append(methods, ssh.Password(r.cfg.SSHPassword))
	}

	return methods
}

func (r *SSHRunner) getClient(sc config.RemoteScannerConfig) (*ssh.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", sc.Host, sc.Port)
	keyFile := r.getKeyFileForScanner(sc)

	// If key file is configured, check if file on disk was modified since connection established
	if keyFile != "" {
		if fi, err := os.Stat(keyFile); err == nil {
			if lastMod, ok := r.clientModTimes[addr]; ok && !fi.ModTime().Equal(lastMod) {
				// Key on disk changed! Close and recycle client.
				if c, ok := r.clients[addr]; ok {
					_ = c.Close()
					delete(r.clients, addr)
					delete(r.clientKeyFiles, addr)
					delete(r.clientModTimes, addr)
				}
			}
		}
	}

	if client, ok := r.clients[addr]; ok {
		return client, nil
	}

	user := sc.User
	if user == "" {
		user = "root"
	}

	clientConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            r.getAuthMethods(sc),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh dial to %s failed: %w", addr, err)
	}

	r.clients[addr] = conn
	if keyFile != "" {
		if fi, err := os.Stat(keyFile); err == nil {
			r.clientKeyFiles[addr] = keyFile
			r.clientModTimes[addr] = fi.ModTime()
		}
	}
	return conn, nil
}

func (r *SSHRunner) removeClient(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[addr]; ok {
		_ = c.Close()
		delete(r.clients, addr)
		delete(r.clientKeyFiles, addr)
		delete(r.clientModTimes, addr)
	}
}

// RunScan runs nmap on the remote gateway over SSH
func (r *SSHRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	sc, ok := r.findScannerConfig(target)
	if !ok {
		return nil, fmt.Errorf("no remote scanner configured for target %s", target)
	}
	gatewayName := fmt.Sprintf("%s (%s)", sc.ID, sc.Host)
	addr := fmt.Sprintf("%s:%d", sc.Host, sc.Port)

	client, err := r.getClient(*sc)
	if err != nil {
		return nil, &RemoteScannerError{Gateway: gatewayName, Target: target, Err: err}
	}

	session, err := client.NewSession()
	if err != nil {
		// Connection might be stale, retry once
		r.removeClient(addr)
		client, err = r.getClient(*sc)
		if err != nil {
			return nil, &RemoteScannerError{Gateway: gatewayName, Target: target, Err: err}
		}
		session, err = client.NewSession()
		if err != nil {
			return nil, &RemoteScannerError{Gateway: gatewayName, Target: target, Err: err}
		}
	}
	defer session.Close()

	// Handle context cancellation
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Signal(ssh.SIGKILL)
			_ = session.Close()
		case <-done:
		}
	}()

	prefix := "nmap"
	if sc.Sudo {
		prefix = "sudo -n nmap"
	}
	cmd := fmt.Sprintf("%s %s", prefix, strings.Join(args, " "))
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	runErr := session.Run(cmd)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if runErr != nil {
		errOutput := strings.TrimSpace(stderr.String() + " " + stdout.String())
		isMissing := false
		if exitErr, ok := runErr.(*ssh.ExitError); ok && exitErr.ExitStatus() == 127 {
			isMissing = true
		} else if strings.Contains(strings.ToLower(errOutput), "not found") || strings.Contains(strings.ToLower(errOutput), "no such file") {
			isMissing = true
		}

		errMsg := errOutput
		if errMsg == "" {
			errMsg = runErr.Error()
		}

		return nil, &RemoteScannerError{
			Gateway:       gatewayName,
			Target:        target,
			Err:           fmt.Errorf("%s", errMsg),
			IsMissingNmap: isMissing,
		}
	}

	return stdout.Bytes(), nil
}

// Close closes all pooled SSH client connections
func (r *SSHRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for addr, client := range r.clients {
		_ = client.Close()
		delete(r.clients, addr)
	}
	return nil
}
