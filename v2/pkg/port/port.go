package port

import (
	"fmt"

	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

type Service struct {
	Name      string   `json:"name"`
	Product   string   `json:"product"`
	ExtraInfo string   `json:"extrainfo"`
	CPEs      []string `json:"cpes"`

	State string `json:"state"`
}

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	TLS      bool              `json:"tls"`

	Service Service `json:"service"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
