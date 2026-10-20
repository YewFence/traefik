package acme

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/safe"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
)

type cleanupStore struct {
	saved []*CertAndStore
	err   error
}

func (s *cleanupStore) GetAccount(string) (*Account, error) { return nil, nil }
func (s *cleanupStore) SaveAccount(string, *Account) error  { return nil }
func (s *cleanupStore) GetCertificates(string) ([]*CertAndStore, error) {
	return s.saved, nil
}

func (s *cleanupStore) SaveCertificates(_ string, certificates []*CertAndStore) error {
	if s.err != nil {
		return s.err
	}
	s.saved = certificates
	return nil
}

func cleanupTestCertificate(t *testing.T) *CertAndStore {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"api.example.com", "*.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return &CertAndStore{Certificate: Certificate{
		Domain:      types.Domain{Main: "api.example.com"},
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Key:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	}, Store: traefiktls.DefaultTLSStoreName}
}

func TestCertificateIsReferenced(t *testing.T) {
	cert := cleanupTestCertificate(t)
	tests := []struct {
		name       string
		config     dynamic.Configuration
		referenced bool
	}{
		{
			name: "http host regexp",
			config: dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
				"router": {Rule: "HostRegexp(`^[a-z]+\\.example\\.com$`)", TLS: &dynamic.RouterTLSConfig{CertResolver: "resolver"}},
			}}},
			referenced: true,
		},
		{
			name: "router with another resolver can use certificate",
			config: dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
				"router": {Rule: "Host(`api.example.com`)", TLS: &dynamic.RouterTLSConfig{CertResolver: "other"}},
			}}},
			referenced: true,
		},
		{
			name: "router without resolver uses actual wildcard SAN",
			config: dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
				"router": {Rule: "HostRegexp(`^web\\.example\\.net$`)", TLS: &dynamic.RouterTLSConfig{}},
			}}},
			referenced: true,
		},
		{
			name: "unrelated regexp does not retain certificate",
			config: dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
				"router": {Rule: "HostRegexp(`^web\\.example\\.org$`)", TLS: &dynamic.RouterTLSConfig{}},
			}}},
		},
		{
			name: "tcp regexp",
			config: dynamic.Configuration{TCP: &dynamic.TCPConfiguration{Routers: map[string]*dynamic.TCPRouter{
				"router": {Rule: "HostSNIRegexp(`^db\\.example\\.net$`)", TLS: &dynamic.RouterTCPTLSConfig{}},
			}}},
			referenced: true,
		},
		{
			name: "passthrough router does not consume certificate",
			config: dynamic.Configuration{TCP: &dynamic.TCPConfiguration{Routers: map[string]*dynamic.TCPRouter{
				"router": {Rule: "HostSNI(`api.example.com`)", TLS: &dynamic.RouterTCPTLSConfig{Passthrough: true}},
			}}},
		},
		{
			name: "explicit domains do not hide rule references",
			config: dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
				"router": {Rule: "Host(`api.example.com`)", TLS: &dynamic.RouterTLSConfig{Domains: []types.Domain{{Main: "other.example.org"}}}},
			}}},
			referenced: true,
		},
		{
			name: "default generated certificate",
			config: dynamic.Configuration{TLS: &dynamic.TLSConfiguration{Stores: map[string]traefiktls.Store{
				traefiktls.DefaultTLSStoreName: {DefaultGeneratedCert: &traefiktls.GeneratedCert{Domain: &types.Domain{Main: "api.example.com"}, Resolver: "resolver"}},
			}}},
			referenced: true,
		},
		{
			name: "invalid regexp retains certificate",
			config: dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
				"router": {Rule: "HostRegexp(`[`)", TLS: &dynamic.RouterTLSConfig{}},
			}}},
			referenced: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.referenced, certificateIsReferenced(t.Context(), cert, test.config))
		})
	}
}

func TestProviderCleanupUnusedCertificates(t *testing.T) {
	tests := []struct {
		name     string
		grace    time.Duration
		observed bool
		unused   time.Duration
		storeErr error
		removed  bool
	}{
		{name: "after grace", grace: time.Minute, observed: true, unused: 2 * time.Minute, removed: true},
		{name: "within grace", grace: time.Minute, observed: true, unused: time.Second},
		{name: "disabled", observed: true, unused: 2 * time.Minute},
		{name: "startup without configuration", grace: time.Minute, unused: 2 * time.Minute},
		{name: "storage failure retains certificate", grace: time.Minute, observed: true, unused: 2 * time.Minute, storeErr: errors.New("storage unavailable")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert := cleanupTestCertificate(t)
			store := &cleanupStore{saved: []*CertAndStore{cert}, err: test.storeErr}
			messages := make(chan dynamic.Message, 1)
			provider := &Provider{
				Configuration:     &Configuration{CertificatesCleanupGracePeriod: ptypes.Duration(test.grace)},
				ResolverName:      "resolver",
				Store:             store,
				certificates:      []*CertAndStore{cert},
				unusedSince:       map[string]time.Time{certificateKey(cert): time.Now().Add(-test.unused)},
				configObserved:    test.observed,
				configurationChan: messages,
			}
			provider.cleanupUnusedCertificates(t.Context())
			if test.removed {
				assert.Empty(t, provider.certificates)
				assert.Empty(t, store.saved)
				require.Len(t, messages, 1)
				assert.Empty(t, (<-messages).Configuration.TLS.Certificates)
			} else {
				assert.Equal(t, []*CertAndStore{cert}, provider.certificates)
				assert.Equal(t, []*CertAndStore{cert}, store.saved)
				assert.Empty(t, messages)
			}
		})
	}
}

func TestProviderObserveCertificateUsageRestoresUnusedCertificate(t *testing.T) {
	cert := cleanupTestCertificate(t)
	provider := &Provider{ResolverName: "resolver", certificates: []*CertAndStore{cert}}
	provider.observeCertificateUsage(t.Context(), dynamic.Configuration{})
	firstUnused := provider.unusedSince[certificateKey(cert)]
	require.False(t, firstUnused.IsZero())
	provider.observeCertificateUsage(t.Context(), dynamic.Configuration{})
	assert.Equal(t, firstUnused, provider.unusedSince[certificateKey(cert)])

	provider.observeCertificateUsage(t.Context(), dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{
		"remaining@file": {Rule: "Host(`api.example.com`)", TLS: &dynamic.RouterTLSConfig{}},
	}}})
	assert.NotContains(t, provider.unusedSince, certificateKey(cert))

	provider.observeCertificateUsage(t.Context(), dynamic.Configuration{})
	assert.False(t, provider.unusedSince[certificateKey(cert)].Before(firstUnused))
}

func TestProviderTracksCertificateObtainedAfterRouterDisappears(t *testing.T) {
	cert := cleanupTestCertificate(t)
	provider := &Provider{
		Store: &cleanupStore{}, configurationChan: make(chan dynamic.Message, 2),
	}
	provider.observeCertificateUsage(t.Context(), dynamic.Configuration{})
	resource := &certificate.Resource{Certificate: cert.Certificate.Certificate, PrivateKey: cert.Key}
	require.NoError(t, provider.addCertificateForDomain(cert.Domain, resource, cert.Store))
	firstUnused := provider.unusedSince[certificateKey(cert)]
	require.False(t, firstUnused.IsZero())
	require.NoError(t, provider.addCertificateForDomain(cert.Domain, resource, cert.Store))
	assert.Equal(t, firstUnused, provider.unusedSince[certificateKey(cert)])
}

func TestCertificateKeyDoesNotMutateDomains(t *testing.T) {
	cert := &CertAndStore{Certificate: Certificate{Domain: types.Domain{SANs: []string{"z.example.com", "a.example.com"}}}}
	certificateKey(cert)
	assert.Equal(t, []string{"z.example.com", "a.example.com"}, cert.Domain.SANs)
}

func TestProviderCleanupPublishesAndPersistsWithoutRestart(t *testing.T) {
	cert := cleanupTestCertificate(t)
	filename := filepath.Join(t.TempDir(), "acme.json")
	pool := safe.NewPool(t.Context())
	defer pool.Stop()
	store := NewLocalStore(filename, pool)
	require.NoError(t, store.SaveCertificates("resolver", []*CertAndStore{cert}))
	require.NoError(t, store.SaveCertificates("other", []*CertAndStore{cert}))
	configuration := &Configuration{}
	configuration.SetDefaults()
	configuration.Storage = filename
	configuration.CertificatesDuration = 24
	configuration.CertificatesCleanupGracePeriod = ptypes.Duration(50 * time.Millisecond)
	provider := &Provider{Configuration: configuration, ResolverName: "resolver", Store: store}
	require.NoError(t, provider.Init())
	provider.SetConfigListenerChan(make(chan dynamic.Configuration))
	messages := make(chan dynamic.Message, 10)
	require.NoError(t, provider.Provide(messages, pool))
	require.Len(t, (<-messages).Configuration.TLS.Certificates, 1)

	provider.ListenConfiguration(dynamic.Configuration{})
	select {
	case message := <-messages:
		assert.Empty(t, message.Configuration.TLS.Certificates)
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not publish a TLS configuration")
	}

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		data, err := os.ReadFile(filename)
		require.NoError(collect, err)
		var stored map[string]struct {
			Certificates []json.RawMessage `json:"Certificates"`
		}
		require.NoError(collect, json.Unmarshal(data, &stored))
		assert.Empty(collect, stored["resolver"].Certificates)
		assert.Len(collect, stored["other"].Certificates, 1)
	}, 5*time.Second, 10*time.Millisecond)
}

func TestProviderDoesNotRenewUnusedCertificateAfterGrace(t *testing.T) {
	cert := cleanupTestCertificate(t)
	provider := &Provider{
		Configuration: &Configuration{CertificatesCleanupGracePeriod: ptypes.Duration(time.Minute)},
		certificates:  []*CertAndStore{cert},
		unusedSince:   map[string]time.Time{certificateKey(cert): time.Now().Add(-2 * time.Minute)},
	}
	provider.renewCertificates(context.Background(), 60*24*time.Hour)
	assert.Nil(t, provider.client)
}
