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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)

	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}

	log.SetFormatter(formatter)
}

const (
	sshListenPort    = "2222"
	sshServerKeyPath = "./tunneled_id_rsa"
	userDataPath     = "./users.json"
)

type SSHServer struct {
	config  *ssh.ServerConfig
	port    string
	tunnels map[string]*Tunnel
	users   map[string]*User
}

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

type RequestDirector struct {
	port string
}

var sshServer = &SSHServer{
	port:    sshListenPort,
	tunnels: map[string]*Tunnel{},
	users:   map[string]*User{},
}

var requestDirector = &RequestDirector{
	port: os.Getenv("DIRECTOR_PORT"),
}

func main() {
	sshServer.loadUsers()

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: sshServer.publicKeyAuthStrategy,
	}

	sshConfig.AddHostKey(sshServer.key())

	sshServer.config = sshConfig

	go sshServer.Start()
	requestDirector.Start()
}

func (server *SSHServer) loadUsers() {
	usersFile, err := os.Open(userDataPath)
	if err != nil {
		log.Panicf("Failed to read users from JSON file: %s", err)
	}

	json.NewDecoder(usersFile).Decode(&server.users)
}

func (server *SSHServer) key() ssh.Signer {
	if _, err := os.Stat(sshServerKeyPath); os.IsNotExist(err) {
		log.Info("SSH server key pair does not exist, creating...")

		err := exec.Command("ssh-keygen", "-f", sshServerKeyPath, "-t", "rsa", "-N", "").Run()
		if err != nil {
			log.Panicf("Failed to create SSH key pair for host: %s", err)
		}

		log.Debug("SSH server key pair created")
	}

	keyBytes, err := ioutil.ReadFile(sshServerKeyPath)
	if err != nil {
		log.Panicf("Failed to load host's private SSH key: %s", err)
	}

	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		log.Panicf("Failed to parse host's private SSH key: %s", err)
	}

	return key
}

func (server *SSHServer) publicKeyAuthStrategy(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	convertPublicKeyToString := func(key ssh.PublicKey) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}

	publicKey := convertPublicKeyToString(key)
	serverPublicKey := convertPublicKeyToString(server.key().PublicKey())

	if publicKey == serverPublicKey {
		return &ssh.Permissions{}, nil
	}

	user := server.users[conn.User()]

	if user != nil && publicKey == user.PublicKey {
		log.Infof("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr())
		user.Login = conn.User()
		return &ssh.Permissions{}, nil
	} else {
		log.Infof("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr())
		return nil, errors.New("Unauthorized access")
	}
}

func (server *SSHServer) Start() {
	log.Info("Starting SSH server...")

	listener, err := net.Listen("tcp", "0.0.0.0:"+server.port)
	if err != nil {
		log.Fatalf("Could not start SSH server: %s", err)
	}

	defer listener.Close()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Warnf("Failed to accept incoming SSH connection: %s", err)
		}

		log.Infof("Beginning SSH handshake for %s", tcpConn.RemoteAddr())

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, server.config)
			if err != nil {
				log.Infof("Failed to handshake from %s: %s", tcpConn.RemoteAddr(), err)
			} else {
				log.Infof("Connection established for %s@%s (%s)", sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion())

				go server.handleRequests(reqs, sshConn)
				go server.handleChannels(chans, sshConn)
			}
		}()
	}
}

func (server *SSHServer) handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn) {
	for req := range reqs {
		if req.Type == "tcpip-forward" {
			user := sshServer.users[conn.User()]

			if user != nil {
				type tcpIpForwardRequestPayload struct {
					Raddr string
					Rport uint32
				}

				var requestPayload tcpIpForwardRequestPayload

				err := ssh.Unmarshal(req.Payload, &requestPayload)
				if err != nil {
					log.Warnf("Malformed tcpip-forward request %s", err)
					req.Reply(false, nil)
				}

				remoteAddr := requestPayload.Raddr
				remotePort := requestPayload.Rport

				domain := user.Subdomain + ".tunneled.computer"

				log.Infof("Creating tunnel from http://%s:%d to %s for %s", domain, remotePort, remoteAddr, user.Login)

				tun := Tunnel{
					user:       user,
					connection: conn,
					remoteAddr: remoteAddr,
					remotePort: remotePort,
				}

				var mutex = &sync.Mutex{}

				mutex.Lock()
				sshServer.tunnels[domain] = &tun
				mutex.Unlock()

				req.Reply(true, []byte{})
			} else {
				log.Warn("Cannot create tunnel for unidentified user")
				req.Reply(false, nil)
			}
		} else {
			log.Warn("Received non tcpip-forward request: %q WantReply=%q: %q", req.Type, req.WantReply, req.Payload)
			req.Reply(false, nil)
		}
	}
}

func (server *SSHServer) handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn) {
	for newChannel := range chans {
		go func() {
			channelType := newChannel.ChannelType()

			if channelType != "direct-tcpip" {
				newChannel.Reject(ssh.Prohibited, "direct-tcpip channels only (-NR)")
				log.Infof("Rejected connection for %s@%s: didn't pass -NR flags", conn.User(), conn.RemoteAddr())
				return
			}
		}()
	}
}

func (server *SSHServer) createChannel(tun Tunnel) (ssh.Channel, error) {
	type forwardedTcpIpRequestPayload struct {
		Raddr string
		Rport uint32
		Laddr string
		Lport uint32
	}

	channelPayload := ssh.Marshal(&forwardedTcpIpRequestPayload{
		Raddr: tun.remoteAddr,
		Rport: tun.remotePort,
		Laddr: "localhost",
		Lport: 8000, // TODO: How can we determine this? https://godoc.org/golang.org/x/crypto/ssh#ConnMetadata
	})

	channel, reqs, err := tun.connection.OpenChannel("forwarded-tcpip", channelPayload)
	if err != nil {
		return nil, err
	}

	go ssh.DiscardRequests(reqs)

	return channel, nil
}

func (director *RequestDirector) Handle404(request net.Conn) {
	response := http.Response{
		Body:       ioutil.NopCloser(bytes.NewBufferString("No tunnel found.")),
		StatusCode: 404,
	}

	err := response.Write(request)
	if err != nil {
		log.Info("Couldn't write 404 response")
	}

	request.Close()
}

func (director *RequestDirector) Start() {
	log.Info("Starting Request Director...")

	listener, err := net.Listen("tcp", ":"+director.port)
	if err != nil {
		log.Fatalf("Could not start listener on port %s: %s", director.port, err)
	}

	for {
		request, err := listener.Accept()
		if err != nil {
			log.Warnf("Could not accept connection: %s", err)
			continue
		}

		var requestBuf bytes.Buffer
		requestReader := io.TeeReader(request, &requestBuf)

		httpRequest, err := http.ReadRequest(bufio.NewReader(requestReader))
		if err != nil {
			log.WithFields(log.Fields{
				"remote_ip": request.RemoteAddr(),
			}).Warnf("Couldn't parse request as HTTP: %s", err)
			continue
		}

		domain := httpRequest.Host

		contextLogger := log.WithFields(log.Fields{
			"remote_ip":          request.RemoteAddr(),
			"destination_domain": domain,
			"destination_path":   httpRequest.URL.Path,
		})

		contextLogger.Info("Incoming request")

		if requestDirector.port != "80" {
			domain, _, err = net.SplitHostPort(domain)
			if err != nil {
				contextLogger.Warnf("Could not split host and port: %s", err)
			}
		}

		var mutex = &sync.Mutex{}

		mutex.Lock()
		tun := sshServer.tunnels[domain]
		mutex.Unlock()

		if tun == nil {
			contextLogger.Infof("Couldn't find a tunnel for: http://%s", domain)

			director.Handle404(request)
			continue
		}

		channel, err := sshServer.createChannel(*tun)
		if err != nil {
			contextLogger.Infof("Couldn't find a tunnel for: http://%s", domain)

			director.Handle404(request)
			continue
		}

		go func() {
			_, err := io.Copy(channel, &requestBuf)
			if err != nil {
				contextLogger.Warnf("Couldn't copy request to tunnel: %s", err)
				request.Close()
				channel.Close()
				return
			}

			channel.CloseWrite()
		}()

		go func() {
			_, err := io.Copy(request, channel)
			if err != nil {
				contextLogger.Warnf("Couldn't copy response from tunnel: %s", err)
				request.Close()
				channel.Close()
				return
			}

			contextLogger.Info("Returned response")

			request.Close()
			channel.Close()
		}()
	}
}
