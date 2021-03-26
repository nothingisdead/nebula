// +build e2e_testing

package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula/pkg/nebula"
)

func TestGoodHandshake(t *testing.T) {
	l := NewTestLogger()
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	defMask := net.IPMask{0, 0, 0, 0}

	myIpNet := &net.IPNet{IP: net.IP{1, 2, 3, 4}, Mask: defMask}
	myControl := newSimpleServer(l, ca, caKey, "me", 1, myIpNet)

	theirIpNet := &net.IPNet{IP: net.IP{1, 2, 3, 4}, Mask: defMask}
	theirControl := newSimpleServer(l, ca, caKey, "them", 2, theirIpNet)

	myControl.Start()
	theirControl.Start()

	myUDPs := myControl.GetUDPConns()
	myUDPs[0].Send(&nebula.UdpPacket{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 12,
		Data: []byte("You should receive this on 127.0.0.1:1"),
	})
	time.Sleep(time.Second)
}
