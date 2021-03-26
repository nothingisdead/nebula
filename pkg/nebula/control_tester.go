// +build e2e_testing

package nebula

type UDPConn interface {
	Send(packet *UdpPacket)
	Get() *UdpPacket
}

func (c *Control) GetUDPConns() []UDPConn {
	conns := make([]UDPConn, len(c.f.writers))
	for k, v := range c.f.writers {
		conns[k] = v
	}
	return conns
}
