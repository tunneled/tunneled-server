package main

import (
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
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
}

func handleServerConn(keyID string, chans <-chan ssh.NewChannel) {
	log.Info("Begin handling server connection...")
}

func createHostKey() {
	cmd := exec.Command("ssh-keygen", "-f", privateHostKeyPath, "-t", "rsa", "-N", "")

	err := cmd.Run()

	if err != nil {
		log.Error("Failed to create private key for host")
		panic(err)
	}

	log.Info("New private host key generated: " + privateHostKeyPath)
}

func loadPrivateHostKey() ssh.Signer {
	privateHostKeyBytes, err := ioutil.ReadFile(privateHostKeyPath)
	if err != nil {
		panic("Failed to load host's private key")
	}

	privateHostKey, err := ssh.ParsePrivateKey(privateHostKeyBytes)
	if err != nil {
		panic("Failed to parse host's private key")
	}

	return privateHostKey
}

func main() {
	var privateHostKey ssh.Signer

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			formattedPrivateKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			log.Info("User's public key is: " + formattedPrivateKey)

			//publicKey, err := models.SearchPublicKeyByContent(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))

			//if err != nil {
			//	log.Error(3, "SearchPublicKeyByContent: %v", err)
			//	return nil, err
			//}
			//return &ssh.Permissions{Extensions: map[string]string{"key-id": com.ToStr(publicKey.ID)}}, nil
			return &ssh.Permissions{Extensions: map[string]string{"key-id": "SUCCESS"}}, nil
		},
	}

	if _, err := os.Stat(privateHostKeyPath); os.IsNotExist(err) {
		log.Info("Host key does not exist, creating...")
		createHostKey()
		privateHostKey = loadPrivateHostKey()
	} else {
		log.Info("Host key exists, continuing...")
		privateHostKey = loadPrivateHostKey()
	}

	config.AddHostKey(privateHostKey)

	log.Info("Listening...")
	listener, err := net.Listen("tcp", "0.0.0.0:2222")

	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error("SSH: Error accepting incoming connection: %v", err)
		}

		// Use a separate go routine to establish the handshake to ensure this is non-blocking
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
