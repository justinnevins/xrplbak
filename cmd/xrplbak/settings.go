package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

const settingsName = "xrplbak.settings"

type settings struct {
	RPC      string
	MaxFee   uint64
	Comments string
	Peers    string
}

func (s settings) render() string { return "" }

func parseSettings(text string) (*settings, error) { return nil, errors.New("stub") }

var submitSleep = time.Sleep

type submitExtras struct {
	FeeWait       time.Duration
	ReadBack      bool
	Save          bool
	SettingsPath  string
	SettingsExist bool
	Settings      settings
}

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
