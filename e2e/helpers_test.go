// +build e2e_testing

package e2e

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"net"
	"os"
	"plugin"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/pkg/cert"
	"github.com/slackhq/nebula/pkg/nebula"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"
)

type m map[string]interface{}

func newSimpleServer(l *logrus.Logger, caCrt *cert.NebulaCertificate, caKey []byte, name string, listenPort int, vpnIp *net.IPNet) *nebula.Control {
	_, _, myPrivKey, myPEM := newTestCert(caCrt, caKey, name, time.Now(), time.Now().Add(5*time.Minute), vpnIp, nil, []string{})
	logger := logrus.New()

	caB, err := caCrt.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	mc := m{
		"pki": m{
			"ca":   string(caB),
			"cert": string(myPEM),
			"key":  string(myPrivKey),
		},
		"tun": m{"disabled": true},
		"firewall": m{
			"outbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
			"inbound": []m{{
				"proto": "any",
				"port":  "any",
				"host":  "any",
			}},
		},
		"listen": m{
			"host": "127.0.0.1",
			"port": listenPort,
		},
	}
	cb, err := yaml.Marshal(mc)
	if err != nil {
		panic(err)
	}

	plug, err := plugin.Open("../nebula.so")
	if err != nil {
		panic(err)
	}

	mn, err := plug.Lookup("Main")
	if err != nil {
		panic(err)
	}

	pNebulaMain, ok := mn.(*func (config *nebula.Config, configTest bool, buildVersion string, logger *logrus.Logger, tunFd *int) (*nebula.Control, error))
	if !ok {
		panic("Not a nebula.Main")
	}

	nebulaMain := *pNebulaMain
	config := nebula.NewConfig()
	config.LoadString(string(cb))
	logger.AddHook(&DefaultFieldHook{GetValue: func() string { return name }})

	control, err := nebulaMain(config, false, "e2e-test", logger, nil)
	if err != nil {
		panic(err)
	}

	return control
}

func newTestCaCert(before, after time.Time, ips, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           "test ca",
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           true,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	if len(ips) > 0 {
		nc.Details.Ips = ips
	}

	if len(subnets) > 0 {
		nc.Details.Subnets = subnets
	}

	if len(groups) > 0 {
		nc.Details.Groups = groups
	}

	err = nc.Sign(priv)
	if err != nil {
		panic(err)
	}

	pem, err := nc.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	return nc, pub, priv, pem
}

func newTestCert(ca *cert.NebulaCertificate, key []byte, name string, before, after time.Time, ip *net.IPNet, subnets []*net.IPNet, groups []string) (*cert.NebulaCertificate, []byte, []byte, []byte) {
	issuer, err := ca.Sha256Sum()
	if err != nil {
		panic(err)
	}

	if before.IsZero() {
		before = time.Now().Add(time.Second * -60).Round(time.Second)
	}
	if after.IsZero() {
		after = time.Now().Add(time.Second * 60).Round(time.Second)
	}

	if len(groups) == 0 {
		groups = []string{"test-group1", "test-group2", "test-group3"}
	}

	pub, rawPriv := x25519Keypair()

	nc := &cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:           name,
			Ips:            []*net.IPNet{ip},
			Subnets:        subnets,
			Groups:         groups,
			NotBefore:      time.Unix(before.Unix(), 0),
			NotAfter:       time.Unix(after.Unix(), 0),
			PublicKey:      pub,
			IsCA:           false,
			Issuer:         issuer,
			InvertedGroups: make(map[string]struct{}),
		},
	}

	err = nc.Sign(key)
	if err != nil {
		panic(err)
	}

	pem, err := nc.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	return nc, pub, cert.MarshalX25519PrivateKey(rawPriv), pem
}

func x25519Keypair() ([]byte, []byte) {
	var pubkey, privkey [32]byte
	if _, err := io.ReadFull(rand.Reader, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return pubkey[:], privkey[:]
}

type DefaultFieldHook struct {
	GetValue func() string
}

func (h *DefaultFieldHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *DefaultFieldHook) Fire(e *logrus.Entry) error {
	e.Data["name"] = h.GetValue()
	return nil
}

func NewTestLogger() *logrus.Logger {
	l := logrus.New()

	v := os.Getenv("TEST_LOGS")
	if v == "" {
		l.SetOutput(ioutil.Discard)
		return l
	}

	switch v {
	case "1":
		// This is the default level but we are being explicit
		l.SetLevel(logrus.InfoLevel)
	case "2":
		l.SetLevel(logrus.DebugLevel)
	case "3":
		l.SetLevel(logrus.TraceLevel)
	}

	return l
}