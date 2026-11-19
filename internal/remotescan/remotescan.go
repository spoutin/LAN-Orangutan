package remotescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Runner manages remote scanner dispatch and execution over SSH
type Runner interface {
	HasRemoteScannerForTarget(target string) bool
	GetGatewayForTarget(target string) string
	RunScan(ctx context.Context, target string, args []string) ([]byte, error)
	CanRunPrivileged(target string) bool
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

type dialCall struct {
	done   chan struct{}
	client *ssh.Client
	err    error
}

// SSHRunner implements Runner using SSH connections
type SSHRunner struct {
	cfg            config.RemoteScannersConfig
	clients        map[string]*ssh.Client
	clientKeyFiles map[string]string
	clientModTimes map[string]time.Time
	inflight       map[string]*dialCall
	closed         bool
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
		inflight:       make(map[string]*dialCall),
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

func (r *SSHRunner) getAuthMethods(sc config.RemoteScannerConfig) ([]ssh.AuthMethod, []string, error) {
	var methods []ssh.AuthMethod
	var descs []string
	var loadErrors []string

	// 1. Gateway-specific credentials
	if sc.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(sc.SSHKey))
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
			fp := ssh.FingerprintSHA256(signer.PublicKey())
			descs = append(descs, fmt.Sprintf("gateway in-memory key (%s, %s)", signer.PublicKey().Type(), fp))
		} else {
			loadErrors = append(loadErrors, fmt.Sprintf("gateway %q ssh_key: %v", sc.ID, err))
			log.Printf("[remotescan] gateway %q: failed parsing ssh_key: %v", sc.ID, err)
		}
	} else if sc.SSHKeyFile != "" {
		signer, _, err := parsePrivateKeyFromFile(sc.SSHKeyFile)
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
			fp := ssh.FingerprintSHA256(signer.PublicKey())
			descs = append(descs, fmt.Sprintf("gateway key file %q (%s, %s)", sc.SSHKeyFile, signer.PublicKey().Type(), fp))
		} else {
			loadErrors = append(loadErrors, fmt.Sprintf("gateway %q ssh_key_file %q: %v", sc.ID, sc.SSHKeyFile, err))
			log.Printf("[remotescan] gateway %q: failed reading ssh_key_file %q: %v", sc.ID, sc.SSHKeyFile, err)
		}
	}

	if sc.SSHPassword != "" {
		methods = append(methods, ssh.Password(sc.SSHPassword))
		descs = append(descs, "gateway password")
	}

	if len(methods) > 0 {
		return methods, descs, nil
	}

	// 2. Fallback to top-level shared credentials
	if r.cfg.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(r.cfg.SSHKey))
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
			fp := ssh.FingerprintSHA256(signer.PublicKey())
			descs = append(descs, fmt.Sprintf("shared in-memory key (%s, %s)", signer.PublicKey().Type(), fp))
		} else {
			loadErrors = append(loadErrors, fmt.Sprintf("shared ssh_key: %v", err))
			log.Printf("[remotescan] shared ssh_key: failed parsing key: %v", err)
		}
	} else if r.cfg.SSHKeyFile != "" {
		signer, _, err := parsePrivateKeyFromFile(r.cfg.SSHKeyFile)
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
			fp := ssh.FingerprintSHA256(signer.PublicKey())
			descs = append(descs, fmt.Sprintf("shared key file %q (%s, %s)", r.cfg.SSHKeyFile, signer.PublicKey().Type(), fp))
		} else {
			loadErrors = append(loadErrors, fmt.Sprintf("shared ssh_key_file %q: %v", r.cfg.SSHKeyFile, err))
			log.Printf("[remotescan] shared ssh_key_file %q: failed reading file: %v", r.cfg.SSHKeyFile, err)
		}
	}

	if r.cfg.SSHPassword != "" {
		methods = append(methods, ssh.Password(r.cfg.SSHPassword))
		descs = append(descs, "shared password")
	}

	if len(methods) > 0 {
		return methods, descs, nil
	}

	if len(loadErrors) > 0 {
		return nil, nil, fmt.Errorf("no valid SSH authentication methods available for gateway %q: %s", sc.ID, strings.Join(loadErrors, "; "))
	}

	return nil, nil, fmt.Errorf("no SSH authentication configured for gateway %q (specify ssh_key_file, ssh_key, or ssh_password)", sc.ID)
}

func (r *SSHRunner) clientPoolKey(sc config.RemoteScannerConfig) string {
	user := sc.User
	if user == "" {
		user = "root"
	}
	h := sha256.New()
	writeField := func(v string) {
		_, _ = fmt.Fprintf(h, "%d:%s\n", len(v), v)
	}
	writeField(sc.SSHKey)
	writeField(sc.SSHKeyFile)
	writeField(sc.SSHPassword)
	writeField(sc.SSHHostKey)
	writeField(sc.SSHKnownHostsFile)
	writeField(fmt.Sprintf("%t:%t", sc.SSHInsecureHostKey, sc.SSHInsecureHostKeySet))
	writeField(r.cfg.SSHKey)
	writeField(r.cfg.SSHKeyFile)
	writeField(r.cfg.SSHPassword)
	writeField(r.cfg.SSHKnownHostsFile)
	writeField(fmt.Sprintf("%t", r.cfg.SSHInsecureHostKey))
	fp := hex.EncodeToString(h.Sum(nil))[:16]
	return fmt.Sprintf("%s:%d:%s:%s", sc.Host, sc.Port, user, fp)
}

func dialSSHClient(ctx context.Context, addr string, clientConfig *ssh.ClientConfig) (*ssh.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	handshakeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-handshakeDone:
		}
	}()

	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, clientConfig)
	close(handshakeDone)
	if err != nil {
		_ = rawConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func (r *SSHRunner) getClient(ctx context.Context, sc config.RemoteScannerConfig) (*ssh.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	addr := fmt.Sprintf("%s:%d", sc.Host, sc.Port)
	key := r.clientPoolKey(sc)
	keyFile := r.getKeyFileForScanner(sc)

	for {
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return nil, fmt.Errorf("ssh runner is closed")
		}

		// If key file is configured, check if file on disk was modified since connection established
		if keyFile != "" {
			if fi, err := os.Stat(keyFile); err == nil {
				if lastMod, ok := r.clientModTimes[key]; ok && !fi.ModTime().Equal(lastMod) {
					// Key on disk changed! Close and recycle client.
					if c, ok := r.clients[key]; ok {
						_ = c.Close()
						delete(r.clients, key)
						delete(r.clientKeyFiles, key)
						delete(r.clientModTimes, key)
					}
				}
			}
		}

		if client, ok := r.clients[key]; ok {
			r.mu.Unlock()
			return client, nil
		}

		if call, ok := r.inflight[key]; ok {
			r.mu.Unlock()
			select {
			case <-call.done:
				if call.err != nil {
					return nil, call.err
				}
				return call.client, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		call := &dialCall{done: make(chan struct{})}
		if r.inflight == nil {
			r.inflight = make(map[string]*dialCall)
		}
		r.inflight[key] = call
		r.mu.Unlock()

		user := sc.User
		if user == "" {
			user = "root"
		}

		var conn *ssh.Client
		var dialErr error

		authMethods, authDescs, err := r.getAuthMethods(sc)
		if err != nil {
			dialErr = err
		} else {
			descStr := strings.Join(authDescs, ", ")
			hostKeyCallback, hkErr := r.getHostKeyCallback(sc)
			if hkErr != nil {
				dialErr = hkErr
			} else {
				clientConfig := &ssh.ClientConfig{
					User:            user,
					Auth:            authMethods,
					HostKeyCallback: hostKeyCallback,
					Timeout:         10 * time.Second,
				}
				conn, dialErr = dialSSHClient(ctx, addr, clientConfig)
				if dialErr != nil {
					dialErr = fmt.Errorf("ssh dial to %s as user %q using %s failed: %w", addr, user, descStr, dialErr)
				} else {
					log.Printf("[remotescan] gateway %q: connected to %s as user %q using %s", sc.ID, addr, user, descStr)
				}
			}
		}

		r.mu.Lock()
		delete(r.inflight, key)
		if dialErr == nil {
			if r.closed {
				_ = conn.Close()
				conn = nil
				dialErr = fmt.Errorf("ssh runner is closed")
			} else {
				r.clients[key] = conn
				if keyFile != "" {
					if fi, err := os.Stat(keyFile); err == nil {
						r.clientKeyFiles[key] = keyFile
						r.clientModTimes[key] = fi.ModTime()
					}
				}
			}
		}
		call.client = conn
		call.err = dialErr
		close(call.done)
		r.mu.Unlock()

		return conn, dialErr
	}
}

func (r *SSHRunner) getHostKeyCallback(sc config.RemoteScannerConfig) (ssh.HostKeyCallback, error) {
	if hostKeyStr := strings.TrimSpace(sc.SSHHostKey); hostKeyStr != "" {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyStr))
		if err != nil {
			return nil, fmt.Errorf("invalid ssh_host_key for gateway %q: %w", sc.ID, err)
		}
		return ssh.FixedHostKey(pubKey), nil
	}

	knownHostsFile := strings.TrimSpace(sc.SSHKnownHostsFile)
	if knownHostsFile == "" {
		knownHostsFile = strings.TrimSpace(r.cfg.SSHKnownHostsFile)
	}
	if knownHostsFile != "" {
		cb, err := knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading ssh_known_hosts_file %q for gateway %q: %w", knownHostsFile, sc.ID, err)
		}
		return cb, nil
	}

	if sc.SSHInsecureHostKey || (r.cfg.SSHInsecureHostKey && !sc.SSHInsecureHostKeySet) {
		log.Printf("[remotescan] WARNING: gateway %q: SSH host key verification disabled (ssh_insecure_host_key=true)", sc.ID)
		return ssh.InsecureIgnoreHostKey(), nil
	}

	return nil, fmt.Errorf("SSH host key verification not configured for gateway %q: set ssh_known_hosts_file, ssh_host_key, or ssh_insecure_host_key=true", sc.ID)
}

func (r *SSHRunner) removeClient(key string, failedClient *ssh.Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[key]; ok && (failedClient == nil || c == failedClient) {
		_ = c.Close()
		delete(r.clients, key)
		delete(r.clientKeyFiles, key)
		delete(r.clientModTimes, key)
	}
}

// CanRunPrivileged returns true if the remote gateway configured for the target has sudo enabled
func (r *SSHRunner) CanRunPrivileged(target string) bool {
	sc, ok := r.findScannerConfig(target)
	if !ok {
		return false
	}
	return sc.Sudo
}

// RunScan runs nmap on the remote gateway over SSH
func (r *SSHRunner) RunScan(ctx context.Context, target string, args []string) ([]byte, error) {
	sc, ok := r.findScannerConfig(target)
	if !ok {
		return nil, fmt.Errorf("no remote scanner configured for target %s", target)
	}
	gatewayName := fmt.Sprintf("%s (%s)", sc.ID, sc.Host)

	quotedArgs := make([]string, len(args))
	for i, arg := range args {
		q, err := shellQuote(arg)
		if err != nil {
			return nil, &RemoteScannerError{Gateway: gatewayName, Target: target, Err: err}
		}
		quotedArgs[i] = q
	}

	poolKey := r.clientPoolKey(*sc)

	client, err := r.getClient(ctx, *sc)
	if err != nil {
		return nil, &RemoteScannerError{Gateway: gatewayName, Target: target, Err: err}
	}

	session, err := client.NewSession()
	if err != nil {
		// Connection might be stale, retry once
		r.removeClient(poolKey, client)
		client, err = r.getClient(ctx, *sc)
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
	cmd := prefix
	if len(quotedArgs) > 0 {
		cmd = fmt.Sprintf("%s %s", prefix, strings.Join(quotedArgs, " "))
	}
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
	r.closed = true
	for key, client := range r.clients {
		_ = client.Close()
		delete(r.clients, key)
	}
	clear(r.clientKeyFiles)
	clear(r.clientModTimes)
	return nil
}

func shellQuote(arg string) (string, error) {
	if strings.ContainsRune(arg, '\x00') {
		return "", fmt.Errorf("invalid argument containing NUL byte")
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'", nil
}
