/*

Tunneled Server

This application multiplexes SSH tunnels, proxying HTTP requests to the
appropriate tunnel based on the subdomain of the request. It looks something
like this:

                  ┌────────┐                                          ┌────────┐
                  │        │                                          │        │
                  │        │ ─┐                                    ┌─ │        │
 ─────Request───▶ │        │  └────────────────────────────────────┘  │        │
                  │Tunneled│ ───────────────────────────────────────▶ │Tunneled│
                  │ Server │ ◀─────────────────────────────────────── │ Client │
 ◀────Response─── │        │  ┌────────────────────────────────────┐  │        │
                  │        │ ─┘                                    └─ │        │
                  │        │                                          │        │
                  └────────┘                                          └────────┘

A standard SSH tunnel connects the server and tunnel. HTTP requests bound for a
*.tunneled.computer domain are received by the server, and passed on to the
appropriate client based on the subdomain the user has claimed. Zooming into the
above diagram, we see:

                  ┌────────────────────────────────────────┐  ┌─────────────────
                  │                                        └──┘    Tunnel to
                  │                                        ┌──┐ Alice's Computer
                  │    ┌──────────────┐  ┌────────────┐    │  └─────────────────
                  │    │              │  │            │    │  ┌─────────────────
                  │    │  Request     │  │            │ ┌─▶└──┘    Tunnel to
───────Request────│─┐  │  Director    │  │            │─┘  ┌──┐ Brooks' Computer
                  │ │  │              │  │ SSH Server │ ┌──│  └─────────────────
                  │ └─▶│1. HTTP Parser├─▶│            │◀┘  │  ┌─────────────────
                  │    │              │  │1. Auth     │    └──┘    Tunnel to
                  │    │2. Subdomain  │  │            │    ┌──┐ Cat's Computer
                  │ ┌──│   Lookup     │◀─┤2. Tunnel DB│    │  └─────────────────
                  │ │  │              │  │            │    │  ┌─────────────────
◀──────Response───┤─┘  │3. Tunnel     │  │            │    └──┘    Tunnel to
                  │    │   Connection │  │            │    ┌──┐ Otto's Computer
                  │    │              │  │            │    │  └─────────────────
                  │    └──────────────┘  └────────────┘    │  ┌─────────────────
                  │                                        └──┘    Tunnel to
                  │                                        ┌──┐ Luna's Computer
                  └────────────────────────────────────────┘  └─────────────────

This application consists of two parts:

1. The SSH Server: responsible for establishing connections with SSH clients. It
   handles authentication based on the public keys defined in the `users.json`
   file and stores established connections in an in-memory store. Tunnels are
   lost when the server dies.

2. The Request Director: responsible for handling incoming HTTP requests to the
   server, determining the subdomain, and then passing along the HTTP request to
   the appropriate tunnel. Any responses coming from the tunnel are proxied back
   through the server to the requester.


*/

package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

type User struct {
	Login     string
	PublicKey string
	Subdomain string
}

type Tunnel struct {
	user       *User
	connection ssh.Conn
	remoteAddr string
	remotePort uint32
}

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)

	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}

	log.SetFormatter(formatter)
}

func main() {
	var sshServer = &SSHServer{
		port:    sshListenPort,
		tunnels: map[string]*Tunnel{},
		users:   map[string]*User{},
	}

	var requestDirector = &RequestDirector{
		port:      os.Getenv("DIRECTOR_PORT"),
		sshServer: sshServer,
	}

	go sshServer.Start()
	requestDirector.Start()
}
