package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"

	"github.com/go-kit/kit/log"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/go-spiffe/uri"

	"github.com/spiffe/spire/helpers"
	"github.com/spiffe/spire/pkg/agent/endpoints/server"
	"github.com/spiffe/spire/pkg/agent/keymanager"
	"github.com/spiffe/spire/pkg/agent/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/workloadattestor"
	"github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common/plugin"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/spiffe/spire/pkg/common"
)

var (
	PluginTypeMap = map[string]plugin.Plugin{
		"KeyManager":       &keymanager.KeyManagerPlugin{},
		"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
		"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	}

	MaxPlugins = map[string]int{
		"KeyManager":       1,
		"NodeAttestor":     1,
		"WorkloadAttestor": 1,
	}
)

type Config struct {
	// Address to bind the workload api to
	BindAddress *net.TCPAddr

	// Distinguished Name to use for all CSRs
	CertDN *pkix.Name

	// Directory to store runtime data
	DataDir string

	// Directory for plugin configs
	PluginDir string

	Logger log.Logger

	// Address of SPIRE server
	ServerAddress *net.TCPAddr

	// A channel for receiving errors from agent goroutines
	ErrorCh chan error

	// A channel to trigger agent shutdown
	ShutdownCh chan struct{}

	// Trust domain and associated CA bundle
	TrustDomain url.URL
	TrustBundle *x509.CertPool
}

type Agent struct {
	BaseSVID            []byte
	registrationEntries []*common.RegistrationEntry
	key                 *ecdsa.PrivateKey
	BaseSVIDTTL         int32

	Catalog *helpers.PluginCatalog
	Config  *Config

	grpcServer *grpc.Server

	Cache Cache
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	err := a.initPlugins()
	defer a.stopPlugins()
	if err != nil {
		return err
	}

	err = a.bootstrap()
	if err != nil {
		return err
	}

	err = a.initEndpoints()
	if err != nil {
		return err
	}

	// Main event loop
	a.Config.Logger.Log("msg", "SPIRE Agent is now running")
	for {
		select {
		case err = <-a.Config.ErrorCh:
			return err
		case <-a.Config.ShutdownCh:
			a.grpcServer.GracefulStop()
			return <-a.Config.ErrorCh
		}
	}
	a.Cache = NewCache()
}

func (a *Agent) initPlugins() error {
	a.Config.Logger.Log("msg", "Starting plugins")

	// TODO: Feed log level through/fix logging...
	pluginLogger := hclog.New(&hclog.LoggerOptions{
		Name:  "pluginLogger",
		Level: hclog.LevelFromString("DEBUG"),
	})

	a.Catalog = &helpers.PluginCatalog{
		PluginConfDirectory: a.Config.PluginDir,
		Logger:              pluginLogger,
	}

	a.Catalog.SetMaxPluginTypeMap(MaxPlugins)
	a.Catalog.SetPluginTypeMap(PluginTypeMap)

	err := a.Catalog.Run()
	if err != nil {
		return err
	}

	return nil
}

func (a *Agent) initEndpoints() error {
	a.Config.Logger.Log("msg", "Starting the workload API")
	svc := server.NewService(a.Catalog, a.Config.ShutdownCh)

	endpoints := server.Endpoints{
		PluginInfoEndpoint: server.MakePluginInfoEndpoint(svc),
		StopEndpoint:       server.MakeStopEndpoint(svc),
	}

	a.grpcServer = grpc.NewServer()
	handler := server.MakeGRPCServer(endpoints)
	sriplugin.RegisterServerServer(a.grpcServer, handler)

	listener, err := net.Listen(a.Config.BindAddress.Network(), a.Config.BindAddress.String())
	if err != nil {
		return fmt.Errorf("Error creating GRPC listener: %s", err)
	}

	go func() {
		a.Config.ErrorCh <- a.grpcServer.Serve(listener)
	}()

	return nil
}

func (a *Agent) bootstrap() error {
	a.Config.Logger.Log("msg", "Bootstrapping SPIRE agent")

	// Look up the key manager plugin
	pluginClients := a.Catalog.GetPluginsByType("KeyManager")
	if len(pluginClients) != 1 {
		return fmt.Errorf("Expected only one key manager plugin, found %i", len(pluginClients))
	}
	keyManager := pluginClients[0].(keymanager.KeyManager)

	// Fetch or generate private key
	res, err := keyManager.FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		return err
	}
	if len(res.PrivateKey) > 0 {
		key, err := x509.ParseECPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}

		err = a.loadBaseSVID()
		if err != nil {
			return err
		}
		a.key = key
	} else {
		if a.BaseSVID != nil {
			a.Config.Logger.Log("msg", "Certificate configured but no private key found!")
		}

		a.Config.Logger.Log("msg", "Generating private key for new base SVID")
		res, err := keyManager.GenerateKeyPair(&keymanager.GenerateKeyPairRequest{})
		if err != nil {
			return fmt.Errorf("Failed to generate private key: %s", err)
		}
		key, err := x509.ParseECPrivateKey(res.PrivateKey)
		if err != nil {
			return err
		}
		a.key = key

		// If we're here, we need to attest/Re-attest
		return a.attest()
	}

	a.Config.Logger.Log("msg", "Bootstrapping done")
	return nil
}

// attest the agent, obtain a new Base SVID
func (a *Agent) attest() error {
	a.Config.Logger.Log("msg", "Preparing to attest against %s", a.Config.ServerAddress.String())

	// Look up the node attestor plugin
	pluginClients := a.Catalog.GetPluginsByType("NodeAttestor")
	if len(pluginClients) != 1 {
		return fmt.Errorf("Expected only one node attestor plugin, found %i", len(pluginClients))
	}
	attestor := pluginClients[0].(nodeattestor.NodeAttestor)

	pluginResponse, err := attestor.FetchAttestationData(&nodeattestor.FetchAttestationDataRequest{})
	if err != nil {
		return fmt.Errorf("Failed to get attestation data from plugin: %s", err)
	}

	// Parse the SPIFFE ID, form a CSR with it
	id, err := url.Parse(pluginResponse.SpiffeId)
	if err != nil {
		return fmt.Errorf("Failed to form SPIFFE ID: %s", err)
	}
	csr, err := a.generateCSR(id,a.key)
	if err != nil {
		return fmt.Errorf("Failed to generate CSR for attestation: %s", err)
	}

	serverID := a.Config.TrustDomain
	serverID.Path = "spiffe/cp"
	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{serverID.String()},
		TrustRoots: a.Config.TrustBundle,
	}

	// Configure TLS
	// Since we are bootstrapping, this is explicitly _not_ mTLS
	tlsConfig := spiffePeer.NewTLSConfig([]tls.Certificate{})
	tlsConfig.ClientAuth = tls.NoClientCert
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(a.Config.ServerAddress.String(), dialCreds)
	if err != nil {
		return fmt.Errorf("Could not connect to: %v", err)
	}
	defer conn.Close()
	c := node.NewNodeClient(conn)

	// Perform attestation
	req := &node.FetchBaseSVIDRequest{
		AttestedData: pluginResponse.AttestedData,
		Csr:          csr,
	}

	serverResponse, err := c.FetchBaseSVID(context.Background(), req)
	if err != nil {
		return fmt.Errorf("Failed attestation against spire server: %s", err)
	}

	a.registrationEntries = serverResponse.SvidUpdate.RegistrationEntries
	// Pull base SVID out of the response
	svids := serverResponse.SvidUpdate.Svids
	if len(svids) > 1 {
		a.Config.Logger.Log("msg", "More than one SVID received during attestation!")
	}
	svid, ok := svids[id.String()]
	if !ok {
		return fmt.Errorf("Base SVID not found in attestation response")
	}

	a.BaseSVID = svid.SvidCert
	a.BaseSVIDTTL = svid.Ttl
	a.storeBaseSVID()
	a.Config.Logger.Log("msg", "Attestation complete")
	return nil
}

// Generate a CSR for the given SPIFFE ID
func (a *Agent) generateCSR(spiffeID *url.URL, key *ecdsa.PrivateKey) ([]byte, error) {
	a.Config.Logger.Log("msg", "Generating a CSR for %s", spiffeID.String())

	uriSANs, err := uri.MarshalUriSANs([]string{spiffeID.String()})
	if err != nil {
		return []byte{}, err
	}
	uriSANExtension := []pkix.Extension{{
		Id:       uri.OidExtensionSubjectAltName,
		Value:    uriSANs,
		Critical: true,
	}}

	csrData := &x509.CertificateRequest{
		Subject:            *a.Config.CertDN,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    uriSANExtension,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, csrData, key)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// Read base SVID from data dir and load it
func (a *Agent) loadBaseSVID() error {
	a.Config.Logger.Log("msg", "Loading base SVID from disk")

	certPath := path.Join(a.Config.DataDir, "base_svid.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		a.Config.Logger.Log("msg", "A base SVID could not be found. A new one will be generated")
		return nil
	}

	data, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("Could not read Base SVID at path %s: %s", certPath, err)
	}

	// Sanity check
	_, err = x509.ParseCertificate(data)
	if err != nil {
		return fmt.Errorf("Certificate at %s could not be understood: %s", certPath, err)
	}

	a.BaseSVID = data
	return nil
}

// Write base SVID to storage dir
func (a *Agent) storeBaseSVID() {
	certPath := path.Join(a.Config.DataDir, "base_svid.crt")
	f, err := os.Create(certPath)
	defer f.Close()
	if err != nil {
		a.Config.Logger.Log("msg", "Unable to store Base SVID at path %s!", certPath)
		return
	}

	f.Write(a.BaseSVID)
	f.Sync()

	return
}

func (a *Agent) FetchSVID() error {

	spiffePeer := SPIFFEPeer{TrustDomian: a.Config.TrustDomain}
	tlsConfig := &tls.Config{
		VerifyPeerCertificate: spiffePeer.VerifyPeerCertificate,
		RootCAs:               a.Config.TrustBundle,
		InsecureSkipVerify:    true,
	}
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(a.Config.ServerAddress.String(), dialCreds)
	if err != nil {
		return fmt.Errorf("Could not connect to: %v", err)
	}
	defer conn.Close()
	c := node.NewNodeClient(conn)


	for _, registrationEntry := range a.registrationEntries {

		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return err
		}
		id, err := url.Parse(registrationEntry.SpiffeId)
		if err != nil {
			return err
		}
		csr, err := a.generateCSR(id,key)




		Cache.SetEntry(&CacheEntry{registrationEntry:registrationEntry, SVID:SVID,privateKey:pkey})
	}

	// Perform attestation
	req := &node.FetchSVIDRequest{}

}



func (a *Agent) stopPlugins() {
	a.Config.Logger.Log("msg", "Stopping plugins...")
	if a.Catalog != nil {
		a.Catalog.Stop()
	}
}
