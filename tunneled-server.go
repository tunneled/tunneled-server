package main

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	privateHostKeyPath = "./tunneled.master.key"
	port               = "2222"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
}

func handleServerConn(keyID string, chans <-chan ssh.NewChannel) {
	log.Info("SSH: Begin handling server connection...")
}

func createHostKey() {
	cmd := exec.Command("ssh-keygen", "-f", privateHostKeyPath, "-t", "rsa", "-N", "")

	err := cmd.Run()

	if err != nil {
		panic(fmt.Sprintf("SSH: Failed to create private key for host %s", err))
	}

	log.Info("SSH: New private host key generated: " + privateHostKeyPath)
}

func loadPrivateHostKey() ssh.Signer {
	privateHostKeyBytes, err := ioutil.ReadFile(privateHostKeyPath)
	if err != nil {
		panic("SSH: Failed to load host's private key")
	}

	privateHostKey, err := ssh.ParsePrivateKey(privateHostKeyBytes)
	if err != nil {
		panic("SSH: Failed to parse host's private key")
	}

	return privateHostKey
}

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			formattedPrivateKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			log.Debug("User's private key is: " + formattedPrivateKey)

			return &ssh.Permissions{Extensions: map[string]string{"key-id": "SUCCESS"}}, nil
		},
	}

	if _, err := os.Stat(privateHostKeyPath); os.IsNotExist(err) {
		log.Info("SSH: Host key does not exist, creating...")
		createHostKey()
	}

	privateHostKey := loadPrivateHostKey()

	config.AddHostKey(privateHostKey)

	log.Info("SSH: Listening...")
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)

	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error("SSH: Error accepting incoming connection: %v", err)
		}

		go func() {
			log.Info("SSH: Handshaking for %s", conn.RemoteAddr())
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				if err == io.EOF {
					log.Warn("SSH: Handshaking was terminated: %v", err)
				} else {
					log.Error(3, "SSH: Error on handshaking: %v", err)
				}
				return
			}

			log.Info("SSH: Connection from %s (%s)", sConn.RemoteAddr(), sConn.ClientVersion())
			go ssh.DiscardRequests(reqs)
			go handleServerConn(sConn.Permissions.Extensions["key-id"], chans)
		}()
	}
}
