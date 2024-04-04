package config

import (
	"encoding/json"
	"log"
	"os"
)

const (
	ConfigFileName = `config.json`
)

var (
	instance *config
)

type loginServerConfig struct {
	IP                    string `json:"ip"` // interface
	Port                  int32  `json:"port"`
	CreateMissingAccounts bool   `json:"createMissingAccounts"`
	LogLevel              int8   `json:"loglevel"`
}

type databaseConfig struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
	SSLMode  string `json:"sslmode"`
}

type config struct {
	LoginServer loginServerConfig `json:"loginServer"`
	Database    databaseConfig    `json:"database"`
}

// GetInstance
//
// Returns the configuration as a singleton.
func GetInstance() *config {

	if instance != nil {
		return instance
	}

	instance = &config{}
	instance.init()

	return instance
}

// init
//
// Private function initializing config singleton
func (conf *config) init() {

	var (
		err error

		content []byte
	)

	// read json config content
	content, err = os.ReadFile(ConfigFileName)
	if err != nil {
		log.Fatalf("Could not read from config file %s: %v", ConfigFileName, err)
	}

	// parse json into config object
	err = json.Unmarshal(content, conf)
	if err != nil {
		log.Fatalf("Could not parse config: %v", err)
	}

	return
}
