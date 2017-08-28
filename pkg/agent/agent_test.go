package agent

import (
	"github.com/golang/mock/gomock"
	"github.com/spiffe/sri/helpers"
	"github.com/stretchr/testify/suite"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"

	"crypto/x509"
	"github.com/go-kit/kit/log"
	"github.com/spiffe/sri/pkg/agent/keymanager"
	"github.com/spiffe/sri/pkg/agent/nodeattestor"
	"github.com/spiffe/sri/pkg/agent/workloadattestor"
	"github.com/hashicorp/go-plugin"
	"net"
	"os"
)

type AgentTestSuite struct {
	suite.Suite
	t                 *testing.T
	agent             *Agent
	mockPluginCatalog *helpers.MockPluginCatalogInterface
	mockKeyManager    *keymanager.MockKeyManager
	kmManager         []interface{}
	expectedKey       *ecdsa.PrivateKey
	config            *Config
}

func (suite *AgentTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(suite.t)
	defer mockCtrl.Finish()
	suite.mockPluginCatalog = helpers.NewMockPluginCatalogInterface(mockCtrl)
	suite.mockKeyManager = keymanager.NewMockKeyManager(mockCtrl)

	addr := &net.TCPAddr{net.ParseIP("127.0.0.1"), 8086, ""}
	certDN := &pkix.Name{
		Country:      []string{"testCountry"},
		Organization: []string{"testOrg"}}
	errCh := make(chan error)
	shutdownCh := make(chan struct{})

	suite.config = &Config{BindAddress: addr, CertDN: certDN,
		DataDir:   os.TempDir(),
		PluginDir: os.TempDir(), Logger: log.NewNopLogger(), ServerAddress: addr,
		ErrorCh:    errCh,
		ShutdownCh: shutdownCh}

}

func TestNodeServiceTestSuite(t *testing.T) {
	suite.Run(t, new(AgentTestSuite))
}


func (suite *AgentTestSuite) Testbootstrap() {
	expectedkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.expectedKey = expectedkey
	expectedPublicKey, _ := x509.MarshalPKIXPublicKey(expectedkey)
	expectedPrivateKey, _ := x509.MarshalECPrivateKey(expectedkey)

	kmresp := &keymanager.GenerateKeyPairResponse{
		PublicKey: expectedPublicKey, PrivateKey: expectedPrivateKey}
	kmreq := &keymanager.GenerateKeyPairRequest{}
	suite.mockKeyManager.EXPECT().GenerateKeyPair(
		kmreq).Return(kmresp, nil)
	suite.mockKeyManager.EXPECT().FetchPrivateKey(&keymanager.FetchPrivateKeyRequest{}).Return(
		&keymanager.FetchPrivateKeyResponse{expectedPrivateKey}, nil)
	suite.kmManager = append(suite.kmManager, suite.mockKeyManager)
	suite.mockPluginCatalog.EXPECT().GetPluginsByType("KeyManager").Return(suite.kmManager)
	suite.mockPluginCatalog.EXPECT().Run().Return(nil)
	suite.mockPluginCatalog.EXPECT().SetMaxPluginTypeMap(map[string]int{"KeyManager":1,"NodeAttestor":1,"WorkloadAttestor":1})
	suite.mockPluginCatalog.EXPECT().SetPluginTypeMap(	map[string]plugin.Plugin{
		"KeyManager":       &keymanager.KeyManagerPlugin{},
		"NodeAttestor":     &nodeattestor.NodeAttestorPlugin{},
		"WorkloadAttestor": &workloadattestor.WorkloadAttestorPlugin{},
	})
	suite.agent = New(&AgentConfig{
		PluginCatalog: suite.mockPluginCatalog,
		Config:        suite.config})
	err := suite.agent.bootstrap()
	suite.Require().NoError(err)
	suite.Assert().Equal(expectedkey, suite.agent.key)

}
