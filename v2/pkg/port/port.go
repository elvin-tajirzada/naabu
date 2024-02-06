package port

import (
	"fmt"

	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
)

type Service struct {
	Name      string   `json:"name"`
	Product   string   `json:"product"`
	ExtraInfo string   `json:"extrainfo"`
	Version   string   `json:"version"`
	OSType    string   `json:"ostype"`
	CPEs      []string `json:"cpes"`
}

type Port struct {
	Port     int               `json:"port"`
	Protocol protocol.Protocol `json:"protocol"`
	TLS      bool              `json:"tls"`

	Service Service `json:"service"`
	State   string  `json:"state"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
