package sftp

import (
	"io/ioutil"
	"time"

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

var config *sftpConfig

func parsePrivateKeyIfExists() (ssh.Signer, error) {
	// Check for/parse private key
	if config.KeyFile != "" {
		fileContents, err := ioutil.ReadFile(config.KeyFile)
		if err != nil {
			return nil, err
		}
		privateKey, err := ssh.ParsePrivateKeyWithPassphrase(fileContents, []byte(config.KeyPass))
		if err != nil {
			return nil, err
		}

		return privateKey, err
	}

	return nil, nil
}

var SFTPProcessor = func() backends.Decorator {

	var sshClient *ssh.Client
	var sftpClient *sftp.Client

	// Establish an SSH connection when the server starts

	// Config to be populated by initFunc
	initializer := backends.InitializeWith(func(backendConfig backends.BackendConfig) error {

		// Parse config
		configType := backends.BaseConfig(&sftpConfig{})

		parsedConfig, err := backends.Svc.ExtractConfig(backendConfig, configType)

		if err != nil {
			backends.Log().Fatal(err)
			return err
		}

		config = parsedConfig.(*sftpConfig)

		// Establish an SSH connection
		sshConfig := &ssh.ClientConfig{
			User: config.Username,

			Auth: []ssh.AuthMethod{
				ssh.Password(config.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		// Parse SSH keys
		signers, err := parsePrivateKeyIfExists()
		if err != nil {
			return err
		}
		if signers != nil {
			sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signers))
		}

		sshClient, err = ssh.Dial("tcp", config.Hostname, sshConfig)

		if err != nil {
			backends.Log().Fatal(err.Error())
			return err
		}

		// Now establish an SFTP connection over the SSH tunnel
		sftpClient, err = sftp.NewClient(sshClient)

		if err != nil {
			backends.Log().Fatal(err.Error())
			return err
		}

		// Setup keepalive for SSH
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()

			for {
				<-t.C
				backends.Log().Debugln("Sending keepalive")

				// Check SSH connection health
				_, _, err := sshClient.Conn.SendRequest("keepalive@golang.org", true, nil)
				if err != nil {
					backends.Log().Warnf("Disconnected from server: %s. Attempting to reconnect", err.Error())
					sshClient, err = ssh.Dial("tcp", config.Hostname, sshConfig)
					if err != nil {
						backends.Log().Fatalf("Error whilst attempting to reconnect to server: %s", err.Error())
						continue
					}
				}

				// Check SFTP client health
				_, err = sftpClient.Getwd()
				if err != nil {
					backends.Log().Warnf("SFTP client broken: %s. Attempting to reconnect", err.Error())
					sftpClient, err = sftp.NewClient(sshClient)
					if err != nil {
						backends.Log().Fatalf("Error whilst attempting to re-establish SFTP client: %s", err.Error())
						continue
					}
				}
			}
		}()

		return nil
	})

	// Register initializer
	backends.Svc.AddInitializer(initializer)

	// Cleanly shutdown SFTP connection when stopping
	backends.Svc.AddShutdowner(backends.ShutdownWith(func() error {
		if sftpClient != nil {
			return sftpClient.Close()
		}
		return nil
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
					dataFileName := sftpClient.Join(config.Path, hash+".eml")
					doneFileName := dataFileName + ".done"

					// Create email file
					dataFile, err := sftpClient.Create(dataFileName)

					if err != nil {
						backends.Log().WithError(err).Error("Could not upload file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					// Write to the file
					_, err = dataFile.Write(e.Data.Bytes())
					if err != nil {
						backends.Log().WithError(err).Error("Error whilst uploading file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					err = dataFile.Close()
					if err != nil {
						backends.Log().WithError(err).Error("Error whilst closing data file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					// Now write the done file
					doneFile, err := sftpClient.Create(doneFileName)
					if err != nil {
						backends.Log().WithError(err).Error("Error whilst touching done file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					err = doneFile.Close()
					if err != nil {
						backends.Log().WithError(err).Error("Error whilst closing data file")
						return backends.NewResult(response.Canned.ErrorRelayDenied), backends.StorageError
					}

					backends.Log().Infof("Message delivered to %s", dataFileName)

					return p.Process(e, task)
				}
				return p.Process(e, task)
			},
		)
	}
}
