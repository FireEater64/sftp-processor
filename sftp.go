package sftp

import (
	"errors"
	"io/ioutil"

	"github.com/flashmob/go-guerrilla/backends"
	"github.com/flashmob/go-guerrilla/mail"
	"github.com/flashmob/go-guerrilla/response"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sftpConfig struct {
	Username string `json:"sftp_username,omitempty"`
	Password string `json:"sftp_password,omitempty"`
	KeyFile  string `json:"sftp_keyfile,omitempty"`
	KeyPass  string `json:"sftp_keypass,omitempty"`
	Hostname string `json:"sftp_hostname,omitempty"`
	Path     string `json:"sftp_path,omitempty"`
}

var publisher *Publisher
var sshClient *ssh.Client

// Publisher wraps an SSH connection, and provides methods for saving
// email messages using SFTP
type Publisher struct {
	sshClient *ssh.Client
	path      string
}

// New returns a new SftpPublisher, which uses the given ssh.Client
func New(client *ssh.Client, path string) *Publisher {
	return &Publisher{sshClient: client, path: path}
}

// SaveMessage transfers the given message to the configured SFTP share, then
// writes a '.done' file to signify the end of a successful transfer
func (p *Publisher) SaveMessage(emailHash string, data []byte) error {

	sftpClient, err := p.getSftpClient()
	if err != nil {
		return err
	}

	defer sftpClient.Close()

	// Create email file
	dataFileName := sftpClient.Join(p.path, emailHash+".eml")
	dataFile, err := sftpClient.Create(dataFileName)

	if err != nil {
		return err
	}

	// Write to the file
	bytesWritten, err := dataFile.Write(data)
	if err != nil {
		return err
	}

	if bytesWritten != len(data) {
		return errors.New("Corrupt upload")
	}

	err = dataFile.Close()
	if err != nil {
		return nil
	}

	// Write the .done file
	doneFileName := dataFileName + ".done"
	doneFile, err := sftpClient.Create(doneFileName)
	if err != nil {
		return err
	}

	err = doneFile.Close()
	if err != nil {
		return err
	}

	return nil
}

// Close the underlying clients, and exit gracefully
func (p *Publisher) Close() error {
	if p.sshClient != nil {
		err := p.sshClient.Close()
		if err != nil {
			return err
		}
	}

	p.sshClient = nil
	return nil
}

func (p *Publisher) getSftpClient() (*sftp.Client, error) {
	return sftp.NewClient(p.sshClient)
}

func parsePrivateKeyIfExists(keyFile string, keyPass string) (ssh.Signer, error) {
	// Check for/parse private key
	if keyFile != "" {
		fileContents, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		privateKey, err := ssh.ParsePrivateKeyWithPassphrase(fileContents, []byte(keyPass))
		if err != nil {
			return nil, err
		}

		return privateKey, err
	}

	return nil, nil
}

// SFTPProcessor is the main decorator, to be registered with the Guerilla daemon
var SFTPProcessor = func() backends.Decorator {
	// Establish an SSH connection when the server starts

	// Config to be populated by initFunc
	initializer := backends.InitializeWith(func(backendConfig backends.BackendConfig) error {

		// Parse config
		configType := backends.BaseConfig(&sftpConfig{})

		parsedConfig, err := backends.Svc.ExtractConfig(backendConfig, configType)

		if err != nil {
			print(err)
			return err
		}

		config := parsedConfig.(*sftpConfig)

		// Establish an SSH connection
		sshConfig := &ssh.ClientConfig{
			User: config.Username,

			Auth: []ssh.AuthMethod{
				ssh.Password(config.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		// Parse SSH keys
		signers, err := parsePrivateKeyIfExists(config.KeyFile, config.KeyPass)
		if err != nil {
			return err
		}
		if signers != nil {
			sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signers))
		}

		if sshClient == nil {
			sshClient, err = ssh.Dial("tcp", config.Hostname, sshConfig)

			if err != nil {
				print(err.Error())
				return err
			}
		}

		if publisher == nil {
			publisher = New(sshClient, config.Path)
		}

		if err != nil {
			print(err)
			return err
		}

		return nil
	})

	// Register initializer
	backends.Svc.AddInitializer(initializer)

	// Cleanly shutdown SFTP connection when stopping
	backends.Svc.AddShutdowner(backends.ShutdownWith(func() error {
		return publisher.Close()
	}))

	return func(p backends.Processor) backends.Processor {
		return backends.ProcessWith(
			func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
				if task == backends.TaskSaveMail {

					// Compute filename from email hash
					if len(e.Hashes) == 0 {
						backends.Log().Error("SFTP needs a Hash() process before it")
						result := backends.NewResult(response.Canned.FailBackendTransaction)
						return result, backends.StorageError
					}

					e.QueuedId = e.Hashes[0]
					hash := e.Hashes[0]

					err := publisher.SaveMessage(hash, e.Data.Bytes())

					if err != nil {
						backends.Log().WithError(err).Error("Could not upload file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					backends.Log().Info("%s delivered", hash)

					return p.Process(e, task)
				}
				return p.Process(e, task)
			},
		)
	}
}
