// Copyright (c) 2018-2020, AT&T Intellectual Property Inc.
// All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

package aaa

import (
	"encoding/json"
	"fmt"
	"github.com/danos/utils/guard"
	"github.com/danos/utils/pathutil"
	"log"
	"os"
	"path/filepath"
	"plugin"
)

const AAAPluginsCfgDir = "/etc/aaa-plugins/"
const AAAPluginsDir = "/usr/lib/aaa-plugins/"

const (
	aaaPluginAPIVersionSym = "AAAPluginAPIVersion"
	aaaPluginImplSymFmt    = "AAAPluginV%d"

	AAAPluginAPIVersion = 2
)

type AAAPluginConfig struct {
	CmdAcct   bool   `json:"command-accounting"`
	CmdAuthor bool   `json:"command-authorization"`
	Name      string `json:"name"`
}

type AAATask interface {
	// Account the start of the task
	AccountStart() error

	// Account the end of the task.
	// If provided, the error indicates the task failed with the given error.
	AccountStop(*error) error
}

type AAAPlugin interface {
	// Called on startup and reload, to setup the plugin. Should only return error
	// if the plugin is not usable and should be skipped.
	Setup() error

	// Check if the provided user is valid and required to use this AAA plugin.
	// Should only return an error if the check could not be performed.
	ValidUser(uid uint32, groups []string) (bool, error)

	// Instantiate a task to be subjected to AAA in a protocol specific way.
	// Parameters:
	// - context: provide context if this command is run in conf-mode or op-mode or any
	//            other potential future mode. This should allow the protocol to see
	//            the difference if e.g. "show interfaces" was called in op-mode or
	//            conf-mode.
	// - uid: the UID of the user who originally executed this command/path
	// - groups: the groups the user is member of
	// - path: fully resolved (no abbreviations) path
	// - pathAttrs: metadata of the path
	// - env: map of available environment attributes. Supported mappings are:
	//		tty : a TTY name eg. ttyS0
	NewTask(context string, uid uint32, groups []string, path []string,
		pathAttrs *pathutil.PathAttrs, env map[string]string) (AAATask, error)

	// Authorize a given path the AAA protocol specific way.
	// Parameters:
	// - context: provide context if this command is run in conf-mode or op-mode or any
	//            other potential future mode. This should allow the protocol to see
	//            the difference if e.g. "show interfaces" was called in op-mode or
	//            conf-mode.
	// - uid: the UID of the user who originally executed this command/path
	// - groups: the groups the user is member of
	// - path: fully resolved (no abbreviations) path
	// - pathAttrs: metadata of the path
	//
	// Should only return error if the AAA protocol exhibited an error which prevented
	// the authorization request. In all other cases it should resolve false otherwise.
	// Returning an error will skip the authorization protocol and proceeds with the
	// next authorization protocol if configured and supported.
	Authorize(context string, uid uint32, groups []string, path []string,
		pathAttrs *pathutil.PathAttrs) (bool, error)
}

type AAAProtocol struct {
	Cfg    AAAPluginConfig
	Plugin AAAPlugin
}

type AAA struct {
	Protocols map[string]*AAAProtocol
}

func lookupPluginImpl(name string, p *plugin.Plugin, ver uint32) (AAAPlugin, error) {
	symPluginVersion, err := p.Lookup(aaaPluginAPIVersionSym)
	version, ok := symPluginVersion.(*uint32)
	if !ok {
		err := fmt.Errorf("Unexpected type from " + aaaPluginAPIVersionSym + " symbol")
		return nil, err
	}
	if *version != ver {
		err := fmt.Errorf("Unsupported %s for plugin %s: %d, expected %d",
			aaaPluginAPIVersionSym, name, *version, ver)
		return nil, err
	}

	symPlugin, err := p.Lookup(fmt.Sprintf(aaaPluginImplSymFmt, ver))
	if err != nil {
		err := fmt.Errorf("Could not lookup plugin V%d", ver)
		return nil, err
	}
	var aaaPlugin AAAPlugin
	aaaPlugin, ok = symPlugin.(AAAPlugin)
	if !ok {
		err := fmt.Errorf("Unexpected type from "+aaaPluginImplSymFmt+" symbol", ver)
		return nil, err
	}
	return aaaPlugin, nil
}

func loadAAAPlugin(fn string) (string, *AAAProtocol, error) {
	var cfg AAAPluginConfig
	var protocol AAAProtocol
	f, e := os.Open(AAAPluginsCfgDir + fn)
	if e != nil {
		err := fmt.Errorf("Failed opening plugin config file: %s", e)
		return "", nil, err
	}
	dec := json.NewDecoder(f)
	e = dec.Decode(&cfg)
	if e != nil {
		err := fmt.Errorf("Failed to decode plugin config file: %s", e)
		return "", nil, err
	}

	aaaPlugin, e := plugin.Open(AAAPluginsDir + cfg.Name + ".so")
	if e != nil {
		err := fmt.Errorf("Could not load plugin: %v", e)
		return "", nil, err
	}

	p, err := lookupPluginImpl(cfg.Name, aaaPlugin, AAAPluginAPIVersion)
	if err != nil {
		return "", nil, err
	}

	protocol.Cfg = cfg
	protocol.Plugin = p

	return cfg.Name, &protocol, nil
}

func LoadAAA() (*AAA, error) {
	var aaa AAA

	aaa.Protocols = make(map[string]*AAAProtocol)

	dir, err := os.Open(AAAPluginsCfgDir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.Mode().IsRegular() {
			if filepath.Ext(file.Name()) == ".json" {
				name, protocol, err := loadAAAPlugin(file.Name())
				if err != nil {
					log.Print(err)
					continue
				}
				err = guard.CatchPanicErrorOnly(func() error {
					return protocol.Plugin.Setup()
				})
				if err != nil {
					log.Print(fmt.Sprintf("Error setting up plugin %s: %s", name, err))
					continue
				}
				aaa.Protocols[name] = protocol
			}
		}
	}

	return &aaa, nil
}
