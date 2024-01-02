package runner

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	osutil "github.com/projectdiscovery/utils/os"
)

type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Host struct {
	IP    Address `xml:"address"`
	Ports Ports   `xml:"ports"`
}

type Ports struct {
	Port []Port `xml:"port"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`

	CPEs []string `xml:"cpe"`
}

func (r *Runner) handleNmap() error {
	// command from CLI
	command := r.options.NmapCLI
	hasCLI := r.options.NmapCLI != ""
	if hasCLI {
		var ipsPorts []*result.HostResult
		// build a list of all targets
		for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
			ipsPorts = append(ipsPorts, hostResult)
		}

		// sort by number of ports
		sort.Slice(ipsPorts, func(i, j int) bool {
			return len(ipsPorts[i].Ports) < len(ipsPorts[j].Ports)
		})

		// suggests commands grouping ips in pseudo-exp ranges
		// 0 - 100 ports
		// 100 - 1000 ports
		// 1000 - 10000 ports
		// 10000 - 60000 ports
		ranges := make(map[int][]*result.HostResult) // for better readability
		// collect the indexes corresponding to ranges changes
		for _, ipPorts := range ipsPorts {
			length := len(ipPorts.Ports)
			var index int
			switch {
			case length > 100 && length < 1000:
				index = 1
			case length >= 1000 && length < 10000:
				index = 2
			case length >= 10000:
				index = 3
			default:
				index = 0
			}
			ranges[index] = append(ranges[index], ipPorts)
		}

		for _, rang := range ranges {
			args := strings.Split(command, " ")
			var (
				ips   []string
				ports []string
			)
			allports := make(map[int]struct{})
			for _, ipPorts := range rang {
				ips = append(ips, ipPorts.IP)
				for _, pp := range ipPorts.Ports {
					allports[pp.Port] = struct{}{}
				}
			}
			for p := range allports {
				ports = append(ports, fmt.Sprint(p))
			}

			// if we have no open ports we avoid running nmap
			if len(ports) == 0 {
				continue
			}

			portsStr := strings.Join(ports, ",")
			ipsStr := strings.Join(ips, " ")

			args = append(args, "-p", portsStr)
			args = append(args, ips...)

			// if the command is not executable, we just suggest it
			commandCanBeExecuted := isCommandExecutable(args)

			// if requested via config file or via cli
			if (r.options.Nmap || hasCLI) && commandCanBeExecuted {
				gologger.Info().Msgf("Running nmap command: %s -p %s %s", command, portsStr, ipsStr)
				// check when user type '-nmap-cli "nmap -sV"'
				// automatically remove nmap
				posArgs := 0
				// nmapCommand helps to check if user is on a Windows machine
				nmapCommand := "nmap"
				if args[0] == "nmap" || args[0] == "nmap.exe" {
					posArgs = 1
				}

				// if it's windows search for the executable
				if osutil.IsWindows() {
					nmapCommand = "nmap.exe"
				}

				cmd := exec.Command(nmapCommand, args[posArgs:]...)

				var out bytes.Buffer
				cmd.Stdout = &out
				err := cmd.Run()

				if err != nil {
					errMsg := errors.Wrap(err, "Could not run nmap command")
					gologger.Error().Msgf(errMsg.Error())
					return errMsg
				}

				var nmapRun NmapRun
				err = xml.Unmarshal(out.Bytes(), &nmapRun)
				gologger.Info().Msgf("Nmap command output:\n%s", out.String())
				if err != nil {
					errMsg := errors.Wrap(err, "Could not parse nmap command output")
					gologger.Error().Msgf(errMsg.Error())
					return errMsg
				}

				for _, host := range nmapRun.Hosts {
					for _, port := range host.Ports.Port {
						previousPortInfo := r.scanner.ScanResults.GetPort(host.IP.Addr, port.PortID)
						if previousPortInfo == nil {
							continue
						} else if previousPortInfo.Service.Name != "" {
							continue
						} else {
							gologger.Info().Msgf(
								"Nmap found new service for %s:%d (%s) (%s)",
								host.IP.Addr, port.PortID, port.Service.Name, port.Service.Product,
							)

							previousPortInfo.Service.State = port.State.State
							previousPortInfo.Service.Name = port.Service.Name
							previousPortInfo.Service.Product = port.Service.Product
							previousPortInfo.Service.ExtraInfo = port.Service.ExtraInfo
							previousPortInfo.Service.CPEs = port.Service.CPEs

							r.scanner.ScanResults.UpdatePort(host.IP.Addr, previousPortInfo)
						}
					}
				}
			} else {
				gologger.Info().Msgf("Suggested nmap command: %s -p %s %s", command, portsStr, ipsStr)
			}
		}
	}

	return nil
}

func isCommandExecutable(args []string) bool {
	commandLength := calculateCmdLength(args)
	if osutil.IsWindows() {
		// windows has a hard limit of
		// - 2048 characters in XP
		// - 32768 characters in Win7
		return commandLength < 2048
	}
	// linux and darwin
	return true
}

func calculateCmdLength(args []string) int {
	var commandLength int
	for _, arg := range args {
		commandLength += len(arg)
		commandLength += 1 // space character
	}
	return commandLength
}
