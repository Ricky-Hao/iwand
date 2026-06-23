package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
)

const (
	DefaultListen      = "127.0.0.1:4567"
	DefaultMTU         = 1400
	DefaultExitTUNName = "iwand0"
	MinMTU             = 46
	MaxMTU             = 1600
	maxInterfaceName   = 15
)

type Config struct {
	Listen string       `json:"listen"`
	MTU    uint16       `json:"mtu"`
	DNS    []string     `json:"dns"`
	Exit   ExitConfig   `json:"exit,omitempty"`
	Users  []UserConfig `json:"users"`
}

type UserConfig struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Address      string `json:"address"`
	AllowEncrypt *bool  `json:"allow_encrypt,omitempty"`
}

type ExitConfig struct {
	Enabled      bool   `json:"enabled"`
	TUNName      string `json:"tun_name"`
	TUNAddress   string `json:"tun_address"`
	MTU          uint16 `json:"mtu"`
	StrictSource *bool  `json:"strict_source,omitempty"`
}

type normalizedConfig struct {
	listen string
	mtu    uint16
	dns    []netip.Addr
	exit   normalizedExitConfig
	users  map[string]*configuredUser
}

type normalizedExitConfig struct {
	enabled      bool
	tunName      string
	tunAddress   netip.Prefix
	mtu          uint16
	strictSource bool
}

type configuredUser struct {
	username     string
	password     string
	address      netip.Addr
	allowEncrypt bool
	xorKey       [8]byte
}

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	return DecodeConfig(file)
}

func DecodeConfig(reader io.Reader) (Config, error) {
	var config Config
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("config must contain a single JSON object")
		}
		return Config{}, err
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.MTU < MinMTU || c.MTU > MaxMTU {
		return fmt.Errorf("invalid mtu %d, required %d-%d", c.MTU, MinMTU, MaxMTU)
	}
	if err := c.validateExit(); err != nil {
		return err
	}
	if _, err := net.ResolveUDPAddr("udp", c.Listen); err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.Listen, err)
	}
	if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}

	usernames := make(map[string]struct{}, len(c.Users))
	addresses := make(map[string]struct{}, len(c.Users))
	for index, user := range c.Users {
		if user.Username == "" {
			return fmt.Errorf("users[%d].username is required", index)
		}
		if user.Password == "" {
			return fmt.Errorf("users[%d].password is required", index)
		}
		if user.Address == "" {
			return fmt.Errorf("users[%d].address is required", index)
		}
		if _, exists := usernames[user.Username]; exists {
			return fmt.Errorf("duplicate username %q", user.Username)
		}
		usernames[user.Username] = struct{}{}

		address, err := netip.ParseAddr(user.Address)
		if err != nil {
			return fmt.Errorf("users[%d].address: %w", index, err)
		}
		if !address.Is4() || address.IsUnspecified() {
			return fmt.Errorf("users[%d].address must be a non-zero IPv4 address", index)
		}
		addressKey := address.String()
		if _, exists := addresses[addressKey]; exists {
			return fmt.Errorf("duplicate assigned address %q", addressKey)
		}
		addresses[addressKey] = struct{}{}
	}

	for index, rawDNS := range c.DNS {
		dns, err := netip.ParseAddr(rawDNS)
		if err != nil {
			return fmt.Errorf("dns[%d]: %w", index, err)
		}
		if !dns.Is4() {
			return fmt.Errorf("dns[%d] must be an IPv4 address", index)
		}
	}
	if len(c.DNS) > 2 {
		return errors.New("at most two DNS servers are supported")
	}
	return nil
}

func (c *Config) validateExit() error {
	if !c.Exit.Enabled {
		return nil
	}
	if c.Exit.TUNName == "" {
		c.Exit.TUNName = DefaultExitTUNName
	}
	if len(c.Exit.TUNName) > maxInterfaceName {
		return fmt.Errorf("exit.tun_name %q exceeds Linux interface name limit of %d bytes", c.Exit.TUNName, maxInterfaceName)
	}
	if c.Exit.TUNAddress == "" {
		return errors.New("exit.tun_address is required when exit.enabled is true")
	}
	prefix, err := netip.ParsePrefix(c.Exit.TUNAddress)
	if err != nil {
		return fmt.Errorf("exit.tun_address: %w", err)
	}
	if !prefix.Addr().Is4() || prefix.Addr().IsUnspecified() {
		return errors.New("exit.tun_address must be a non-zero IPv4 prefix")
	}
	if c.Exit.MTU == 0 {
		c.Exit.MTU = c.MTU
	}
	if c.Exit.MTU < MinMTU || c.Exit.MTU > MaxMTU {
		return fmt.Errorf("invalid exit.mtu %d, required %d-%d", c.Exit.MTU, MinMTU, MaxMTU)
	}
	return nil
}

func (c Config) normalized() (normalizedConfig, error) {
	if err := c.validate(); err != nil {
		return normalizedConfig{}, err
	}
	strictSource := true
	if c.Exit.StrictSource != nil {
		strictSource = *c.Exit.StrictSource
	}
	config := normalizedConfig{
		listen: c.Listen,
		mtu:    c.MTU,
		exit: normalizedExitConfig{
			enabled:      c.Exit.Enabled,
			tunName:      c.Exit.TUNName,
			mtu:          c.Exit.MTU,
			strictSource: strictSource,
		},
		users: make(map[string]*configuredUser, len(c.Users)),
	}
	if c.Exit.Enabled {
		config.exit.tunAddress = netip.MustParsePrefix(c.Exit.TUNAddress)
	}
	for _, rawDNS := range c.DNS {
		config.dns = append(config.dns, netip.MustParseAddr(rawDNS))
	}
	for _, rawUser := range c.Users {
		address := netip.MustParseAddr(rawUser.Address)
		allowEncrypt := true
		if rawUser.AllowEncrypt != nil {
			allowEncrypt = *rawUser.AllowEncrypt
		}
		config.users[rawUser.Username] = &configuredUser{
			username:     rawUser.Username,
			password:     rawUser.Password,
			address:      address,
			allowEncrypt: allowEncrypt,
			xorKey:       deriveXORKey(rawUser.Username, rawUser.Password),
		}
	}
	return config, nil
}

func (c Config) UDPAddr() (*net.UDPAddr, error) {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	return net.ResolveUDPAddr("udp", c.Listen)
}
