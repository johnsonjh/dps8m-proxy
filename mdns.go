///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - mdns.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 367608fa-76ec-11f0-80c4-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/mdns"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func announceMDNS(
	listener net.Listener, listenHost string, altHosts map[string]string, service string,
	defaultTarget string,
) {
	laddr := listener.Addr()
	if laddr == nil {
		log.Printf("%sError: mDNS listener.Addr() returned nil (impossible)",
			warnPrefix())

		return
	}

	_, portStr, err := net.SplitHostPort(laddr.String())
	if err != nil {
		log.Printf("%sError parsing host for mDNS announcements: %s",
			warnPrefix(), err)

		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("%sError parsing port for mDNS announcements: %s",
			warnPrefix(), err)

		return
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("%sError getting hostname for mDNS: %v - using default of \"proxy\"",
			toolPrefix(), err)
		hostname = "proxy"
	}

	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	var targetInterfaces []*net.Interface
	var advertiseIPs []net.IP

	allInterfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("%sError enumerating network interfaces for mDNS: %s",
			warnPrefix(), err)

		return
	}

	useAllInterfaces := false

	if listenHost == "0.0.0.0" || listenHost == "::" || listenHost == "" {
		useAllInterfaces = true
	} else {
		ip := net.ParseIP(listenHost)
		if ip != nil {
			if ip.IsLoopback() {
				return
			}

			advertiseIPs = append(advertiseIPs, ip)
		} else {
			ips, err := net.LookupIP(listenHost)
			if err != nil {
				log.Printf(
					"%sError resolving \"%s\" for mDNS: %v - falling back to all interfaces",
					warnPrefix(), listenHost, err)
				useAllInterfaces = true
			} else {
				for _, resolvedIP := range ips {
					if !resolvedIP.IsLoopback() {
						advertiseIPs = append(advertiseIPs, resolvedIP)
					}
				}
			}
		}
	}

	if useAllInterfaces {
		for i, iface := range allInterfaces {
			if (iface.Flags&net.FlagUp) != 0 &&
				(iface.Flags&net.FlagLoopback) == 0 &&
				(iface.Flags&net.FlagMulticast) != 0 {
				targetInterfaces = append(targetInterfaces, &allInterfaces[i])
			}
		}
	} else {
		for i, iface := range allInterfaces {
			if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				var ip net.IP

				ipnet, ok := addr.(*net.IPNet)
				if ok {
					ip = ipnet.IP
				} else {
					ipaddr, ok := addr.(*net.IPAddr)
					if ok {
						ip = ipaddr.IP
					}
				}

				for _, adIP := range advertiseIPs {
					if ip != nil && ip.Equal(adIP) {
						targetInterfaces = append(targetInterfaces, &allInterfaces[i])

						break
					}
				}
			}
		}
	}

	if len(targetInterfaces) == 0 {
		log.Printf("%sNo suitable interfaces found for mDNS announcement.",
			warnPrefix())

		return
	}

	for _, iface := range targetInterfaces {
		var ifaceIPs []net.IP

		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("%sError getting addresses for interface %s: %s",
				warnPrefix(), iface.Name, err)

			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP

			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && !ip.IsLoopback() {
				if ip.To4() != nil {
					ifaceIPs = append(ifaceIPs, ip)
				}
			}
		}

		if len(ifaceIPs) == 0 {
			continue
		}

		defaultTxt := []string{
			"user=default",
			"target=" + defaultTarget,
		}

		defaultInstance := fmt.Sprintf("default-%d",
			port)
		defaultService, err := mdns.NewMDNSService(
			defaultInstance, service, "local.", hostname, port, ifaceIPs, defaultTxt)
		if err != nil {
			log.Printf("%sError creating default mDNS service for interface %s: %s",
				alertPrefix(), iface.Name, err)

			continue
		}

		defaultServer, err := mdns.NewServer(
			&mdns.Config{
				Zone:  defaultService,
				Iface: iface,
			},
		)
		if err != nil {
			log.Printf("%sError creating default mDNS server for interface %s: %s",
				alertPrefix(), iface.Name, err)

			continue
		}

		go func() {
			<-shutdownSignal
			_ = defaultServer.Shutdown()
		}()

		for name, addr := range altHosts {
			txt := []string{
				"user=" + name,
				"target=" + addr,
			}

			altInstance := fmt.Sprintf("%s-%d",
				name, port)
			altHostService, err := mdns.NewMDNSService(
				altInstance, service, "local.", hostname, port, ifaceIPs, txt)
			if err != nil {
				log.Printf("Error creating mDNS service for %s on interface %s: %s",
					name, iface.Name, err)

				continue
			}

			altServer, err := mdns.NewServer(
				&mdns.Config{
					Zone:  altHostService,
					Iface: iface,
				},
			)
			if err != nil {
				log.Printf("%sError creating mDNS server for %s on interface %s: %s",
					alertPrefix(), name, iface.Name, err)

				continue
			}

			go func() {
				<-shutdownSignal
				_ = altServer.Shutdown()
			}()
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
