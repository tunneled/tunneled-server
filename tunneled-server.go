// Notes
// https://github.com/pivotal-cf-experimental/remote-pairing-release/blob/master/src/github.com/pivotal-cf-experimental/ssh-tunnel/server.go#L298
// https://github.com/Sirupsen/logrus
// https://github.com/emulbreh/sshub/blob/c14f516babcc121ae62de2ada5ebffd779e4d6b6/libsshub/hub.go
// https://github.com/Kane-Sendgrid/wormhole/blob/53cd61266020a26a2464439885560f8cf11b9d24/ssh.go#L180
// ssh -NR 8001:localhost:8000 brooks@localhost -p 2222

package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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
}

const (
	privateHostKeyPath = "./tunneled.master.key"
	port               = "2222"
)

type tunnel struct {
	user            *user
	source          string
	destinationPort uint32
	connection      *ssh.ServerConn
}

//TODO: Find a better name
type tcpIpForwardPayload struct {
	BindIP   string
	BindPort uint32
}

type tunnelServer struct {
	config  *ssh.ServerConfig
	port    string
	tunnels map[string]*tunnel
	users   map[string]*user
	sync.Mutex
}

type user struct {
	login     string
	publicKey string
	subdomain string
}

var server = &tunnelServer{
	port:    port,
	tunnels: map[string]*tunnel{},
	users:   map[string]*user{},
}

func main() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: authorizeByPublicKey,
	}

	hostKey := findOrCreateHostKey()
	sshConfig.AddHostKey(hostKey)

	server.config = sshConfig
	server.hydrateUsers()

	server.Start()
}

func findOrCreateHostKey() ssh.Signer {
	if _, err := os.Stat(privateHostKeyPath); os.IsNotExist(err) {
		log.Info("Host SSH key pair does not exist, creating...")

		err := exec.Command("ssh-keygen", "-f", privateHostKeyPath, "-t", "rsa", "-N", "").Run()
		if err != nil {
			log.Panic(fmt.Sprintf("Failed to create key pair for host %s", err))
		} else {
			log.Debug("Host key pair created")
		}
	}

	hostKeyBytes, err := ioutil.ReadFile(privateHostKeyPath)
	if err != nil {
		log.Panic("Failed to load host's private SSH key")
	}

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Panic("Failed to parse host's private SSH key")
	}

	return hostKey
}

func convertPublicKeyToString(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func authorizeByPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	user := server.users[conn.User()]
	publicKey := convertPublicKeyToString(key)
	serverPublicKey := convertPublicKeyToString(findOrCreateHostKey().PublicKey())

	if publicKey == serverPublicKey {
		return &ssh.Permissions{}, nil
	} else if user != nil && user.publicKey == publicKey {
		log.Debug(fmt.Sprintf("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr()))
		return &ssh.Permissions{}, nil
	} else {
		log.Debug(fmt.Sprintf("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr()))
		return nil, errors.New("Unauthorized access")
	}
}

func (server *tunnelServer) hydrateUsers() {
	server.users["bswinnerton"] = &user{
		login:     "brooks",
		subdomain: "noodlepuff.com",
		publicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCVn/shbTiKA+cfiqtQukE7Tb883fB7mOia7GJzwNBXUe8mB0yMJTmE34L8ZhOv+8+RNMFUAY+YMjFqcRRwhh3NKI3CQQZEU/Ka6YXCwuBrdQipHjwRiZjhyS47rCtnQ+2y1V7CZeCPkIKUZQGa20GdNC8+U6f26WdZVLAQN+pJ6kyIvnNW4AgTLSJsJqgndYqwJ4aPpL/HTC4DM4WpM01/ep/iuvIQcC+vKAUjwomIcD+R3YScQVWQuRQuIoX22lafwkcupyNkYCEp8EK3XvWP5ezv8EeJOI+CfO4z+mKD+gRztKXt53N+eD9Aew3XfzlJCieWNNuzZ0hfxmPDqn7",
	}
}

func (server *tunnelServer) Start() error {
	log.Info("Starting server...\n")
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)

	if err != nil {
		log.Fatal(fmt.Sprintf("Could not start server: %s", err))
	}

	defer listener.Close()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to accept incoming connection (%s)", err))
		}

		log.Info(fmt.Sprintf("Beginning SSH handshake for %s", tcpConn.RemoteAddr()))

		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, server.config)
			if err != nil {
				log.Info(fmt.Sprintf("Failed to handshake from %s: %s\n", tcpConn.RemoteAddr(), err))
			} else {
				log.Info(fmt.Sprintf("Connection established for %s@%s (%s)", sshConn.User(), sshConn.RemoteAddr(), sshConn.ClientVersion()))

				go handleRequests(reqs, sshConn, server)
				go handleChannels(chans, sshConn)
			}
		}()
	}
}

func handleRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn, server *tunnelServer) {
	for req := range reqs {
		if req.Type == "tcpip-forward" {
			var payload tcpIpForwardPayload
			err := ssh.Unmarshal(req.Payload, &payload)
			if err != nil {
				log.Warn(fmt.Sprintf("Malformed request %s", err))
				req.Reply(false, nil)
			}

			user := server.users[conn.User()]
			port := payload.BindPort
			addr := payload.BindIP

			if user != nil {
				log.Info(fmt.Sprintf("Creating tunnel from http://%s:%d to %s for %s\n", user.subdomain, port, addr, user.login))

				tun := tunnel{
					user:            user,
					destinationPort: port,
					source:          addr,
					connection:      conn,
				}

				server.Lock()
				server.tunnels[user.subdomain] = &tun
				server.Unlock()

				startReverseTunnel(tun)
			}

			req.Reply(true, []byte{})
		} else {
			log.Warn("got unexpected request %q WantReply=%q: %q\n", req.Type, req.WantReply, req.Payload)
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
				log.Info(fmt.Sprintf("Rejected connection for %s@%s: didn't pass -NR flags\n", conn.User(), conn.RemoteAddr()))
				return
			}
		}()
	}
}

func startReverseTunnel(tun tunnel) {
	type channelOpenForwardMsg struct {
		raddr string
		rport uint32
		laddr string
		lport uint32
	}

	req := &channelOpenForwardMsg{
		raddr: "localhost",
		rport: 8001,
		laddr: "localhost",
		lport: 8000,
	}

	channel, reqs, err := tun.connection.Conn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		log.Error("failed-to-open-channel: ", err)
		return
	}

	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	listener, err := net.Listen("tcp", "0.0.0.0:8001")
	if err != nil {
		log.Warn(fmt.Sprintf("Could not start listening on 0.0.0.0:8001: ", err))
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Panic(fmt.Sprintf("Could not accept request: ", err))
		}

		defer conn.Close()

		log.Infof("Incoming request from %s", conn.RemoteAddr())

		go func() {
			_, err = io.Copy(conn, channel)
			if err != nil {
				conn.Close()
				log.Info(fmt.Sprintf("Couldn't copy request to tunnel: %s", err))
				return
			}
		}()

		go func() {
			_, err = io.Copy(channel, conn)
			if err != nil {
				conn.Close()
				log.Info(fmt.Sprintf("Couldn't copy request to tunnel: %s", err))
				return
			}
		}()
	}
}
