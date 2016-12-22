// Notes
// https://github.com/pivotal-cf-experimental/remote-pairing-release/blob/master/src/github.com/pivotal-cf-experimental/ssh-tunnel/server.go#L298
// https://github.com/Sirupsen/logrus
// https://github.com/emulbreh/sshub/blob/c14f516babcc121ae62de2ada5ebffd779e4d6b6/libsshub/hub.go
// https://github.com/Kane-Sendgrid/wormhole/blob/53cd61266020a26a2464439885560f8cf11b9d24/ssh.go#L180
// ssh -NR 8001:localhost:8000 brooks@localhost -p 2222

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

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
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
	user.Login = conn.User()

	if user != nil && publicKey == user.PublicKey {
		log.Infof("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr())
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

				go handleRequests(reqs, sshConn)
				go handleChannels(chans, sshConn)
			}
		}()
	}
}

func handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn) {
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

				// TODO: Make this threadsafe
				sshServer.tunnels[domain] = &tun

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

func handleChannels(chans <-chan ssh.NewChannel, conn *ssh.ServerConn) {
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
		Lport: 8000, // TODO: How can we determine this?
	})

	channel, reqs, err := tun.connection.OpenChannel("forwarded-tcpip", channelPayload)
	if err != nil {
		return nil, err
	}

	go ssh.DiscardRequests(reqs)

	return channel, nil
}

func (director *RequestDirector) Start() {
	log.Info("Starting Request Director...")

	if requestDirector.port == "" {
		log.Fatal("The DIRECTOR_PORT environment variable must be set")
	}

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

		defer request.Close()

		var requestBuf bytes.Buffer
		requestReader := io.TeeReader(request, &requestBuf)

		httpRequest, err := http.ReadRequest(bufio.NewReader(requestReader))
		if err != nil {
			log.Warnf("Couldn't parse request as HTTP: %s", err)
			continue
		}

		log.Infof("Incoming request for http://%s", httpRequest.Host)

		domain := httpRequest.Host

		if requestDirector.port != "80" {
			domain, _, err = net.SplitHostPort(httpRequest.Host)
			if err != nil {
				log.Warnf("Could not split host and port: %s", err)
			}
		}

		tun := sshServer.tunnels[domain]
		if tun != nil {
			channel, err := sshServer.createChannel(*tun)
			if err != nil {
				log.Infof("SSH connection severed: %s", err)
				io.WriteString(request, "No tunnel found.\n")
				request.Close()
				continue
			}

			go func() {
				_, err := io.Copy(channel, &requestBuf)
				if err != nil {
					log.Warnf("Couldn't copy request to tunnel: %s", err)
					return
				}
			}()

			go func() {
				_, err := io.Copy(request, channel)
				if err != nil {
					log.Warnf("Couldn't copy response from tunnel: %s", err)
					return
				}

				//FIXME: This doesn't get called until after SSH connection is severed
				log.Infof("Passed response back to http://%s", httpRequest.Host)
			}()
		} else {
			log.Infof("Couldn't find a tunnel for: http://%s", httpRequest.Host)
			io.WriteString(request, "No tunnel found.\n")
			request.Close()
		}
	}
}
