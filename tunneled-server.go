// Notes
// https://github.com/pivotal-cf-experimental/remote-pairing-release/blob/master/src/github.com/pivotal-cf-experimental/ssh-tunnel/server.go#L298
// https://github.com/Sirupsen/logrus
// https://github.com/emulbreh/sshub/blob/c14f516babcc121ae62de2ada5ebffd779e4d6b6/libsshub/hub.go
// https://github.com/Kane-Sendgrid/wormhole/blob/53cd61266020a26a2464439885560f8cf11b9d24/ssh.go#L180
// ssh -NR 8001:localhost:8000 brooks@localhost -p 2222

package main

import (
	"errors"
	"io"
	"io/ioutil"
	"net"
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
	sshServerKeyPath = "./server_id_rsa"
	sshListenPort    = "2222"
)

type sshServer struct {
	config  *ssh.ServerConfig
	port    string
	users   map[string]*user
	tunnels map[string]*tunnel
}

type user struct {
	login     string
	publicKey string
	subdomain string
}

type tunnel struct {
	user       *user
	connection ssh.Conn
	remoteAddr string
	remotePort uint32
}

type requestDirector struct {
	port string
}

var newSSHServer = &sshServer{
	port:    sshListenPort,
	tunnels: map[string]*tunnel{},
	users:   map[string]*user{},
}

var newRequestDirector = &requestDirector{
	port: "8001",
}

func main() {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: newSSHServer.publicKeyAuthStrategy,
	}

	sshConfig.AddHostKey(newSSHServer.key())

	newSSHServer.config = sshConfig
	newSSHServer.populateUsers()

	newSSHServer.Start()
}

func (server *sshServer) key() ssh.Signer {
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

func (server *sshServer) publicKeyAuthStrategy(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	convertPublicKeyToString := func(key ssh.PublicKey) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}

	publicKey := convertPublicKeyToString(key)
	serverPublicKey := convertPublicKeyToString(server.key().PublicKey())

	if publicKey == serverPublicKey {
		return &ssh.Permissions{}, nil
	}

	user := server.users[conn.User()]

	if user != nil && publicKey == user.publicKey {
		log.Infof("Successfully authenticated %s@%s", conn.User(), conn.RemoteAddr())
		return &ssh.Permissions{}, nil
	} else {
		log.Infof("Unauthorized access from %s@%s", conn.User(), conn.RemoteAddr())
		return nil, errors.New("Unauthorized access")
	}
}

// TODO: Move to a database
func (server *sshServer) populateUsers() {
	server.users["bswinnerton"] = &user{
		login:     "brooks",
		subdomain: "noodlepuff.com",
		publicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCVn/shbTiKA+cfiqtQukE7Tb883fB7mOia7GJzwNBXUe8mB0yMJTmE34L8ZhOv+8+RNMFUAY+YMjFqcRRwhh3NKI3CQQZEU/Ka6YXCwuBrdQipHjwRiZjhyS47rCtnQ+2y1V7CZeCPkIKUZQGa20GdNC8+U6f26WdZVLAQN+pJ6kyIvnNW4AgTLSJsJqgndYqwJ4aPpL/HTC4DM4WpM01/ep/iuvIQcC+vKAUjwomIcD+R3YScQVWQuRQuIoX22lafwkcupyNkYCEp8EK3XvWP5ezv8EeJOI+CfO4z+mKD+gRztKXt53N+eD9Aew3XfzlJCieWNNuzZ0hfxmPDqn7",
	}
}

func (server *sshServer) Start() {
	log.Info("Starting SSH server...\n")

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
				log.Infof("Failed to handshake from %s: %s\n", tcpConn.RemoteAddr(), err)
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
			user := newSSHServer.users[conn.User()]

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

				log.Infof("Creating tunnel from http://%s:%d to %s for %s\n", user.subdomain, remotePort, remoteAddr, user.login)

				tun := tunnel{
					user:       user,
					connection: conn,
					remoteAddr: remoteAddr,
					remotePort: remotePort,
				}

				// TODO: Make this threadsafe
				newSSHServer.tunnels[user.subdomain] = &tun

				newRequestDirector.Start(tun)

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
				log.Infof("Rejected connection for %s@%s: didn't pass -NR flags\n", conn.User(), conn.RemoteAddr())
				return
			}
		}()
	}
}

func (server *sshServer) createChannel(tun tunnel) ssh.Channel {
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
		log.Warn("Failed to open channel on tunnel: ", err)
	}

	go ssh.DiscardRequests(reqs)

	return channel
}

func (director *requestDirector) Start(tun tunnel) {
	log.Info("Starting Request Director...\n")

	listener, err := net.Listen("tcp", ":"+director.port)
	if err != nil {
		log.Fatalf("Could not start listener on port %s: %s", director.port, err)
	}

	defer listener.Close()

	for {
		request, err := listener.Accept()
		if err != nil {
			log.Warnf("Could not accept connection: %s", err)
		}

		// TODO: Determine tunnel independent of tun argument

		channel := newSSHServer.createChannel(tun)

		go func() {
			_, err := io.Copy(channel, request)
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
		}()
	}
}
