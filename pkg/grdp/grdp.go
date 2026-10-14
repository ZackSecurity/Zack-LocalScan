// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package grdp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"Zack-LocalScan/pkg/grdp/core"
	"Zack-LocalScan/pkg/grdp/glog"
	"Zack-LocalScan/pkg/grdp/protocol/nla"
	"Zack-LocalScan/pkg/grdp/protocol/pdu"
	"Zack-LocalScan/pkg/grdp/protocol/rfb"
	"Zack-LocalScan/pkg/grdp/protocol/sec"
	"Zack-LocalScan/pkg/grdp/protocol/t125"
	"Zack-LocalScan/pkg/grdp/protocol/tpkt"
	"Zack-LocalScan/pkg/grdp/protocol/x224"
)

// Timeout is the connection timeout for RDP dial. Hardcoded 5s — TCP+TLS+x224+MCS+NLA multi-stage negotiation.
var Timeout = 5 * time.Second

const (
	PROTOCOL_RDP = "PROTOCOL_RDP"
	PROTOCOL_SSL = "PROTOCOL_SSL"
)

type Client struct {
	Host string // ip:port
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
	vnc  *rfb.RFB
}

func NewClient(host string, logLevel glog.LEVEL) *Client {
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &Client{
		Host: host,
	}
}

func (g *Client) loginForSSL(domain, user, pwd string) error {
	conn, err := net.DialTimeout("tcp", g.Host, Timeout)
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	defer conn.Close()
	// Set a deadline so the entire multi-stage handshake cannot hang.
	conn.SetDeadline(time.Now().Add(Timeout))
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)

	err = g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	glog.Info("wait connect ok")

	var wg sync.WaitGroup
	var doneOnce sync.Once
	wg.Add(1)

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		err = nil
		glog.Info("on success")
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		glog.Info("on ready")
		g.pdu.Emit("done")
	})
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("on update:", rectangles)
	})
	g.pdu.On("done", func() {
		doneOnce.Do(func() { wg.Done() })
	})

	// Wait for handshake completion or timeout.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(Timeout):
		doneOnce.Do(func() {
			wg.Done()
			err = errors.New("login timeout")
		})
	}
	return err
}

func (g *Client) loginForRDP(domain, user, pwd string) error {
	conn, err := net.DialTimeout("tcp", g.Host, Timeout)
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	defer conn.Close()
	// Set a deadline so the entire multi-stage handshake cannot hang.
	conn.SetDeadline(time.Now().Add(Timeout))
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)

	g.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)

	err = g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	glog.Info("wait connect ok")

	var wg sync.WaitGroup
	var doneOnce sync.Once
	updateCount := 0
	wg.Add(1)

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		err = nil
		glog.Info("on success")
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		glog.Info("on ready")
	})
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("on update:", rectangles)
		updateCount += 1
			})
	g.pdu.On("done", func() {
		doneOnce.Do(func() { wg.Done() })
	})

	// Wait for handshake completion or timeout.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(Timeout):
		doneOnce.Do(func() {
			wg.Done()
			err = errors.New("login timeout")
		})
	}

	// Any bitmap update after auth means the server rendered a desktop → success.
	// (RDP only sends bitmap data after successful MCS + security exchange + licensing.)
	if updateCount >= 1 {
		return nil
	}
	err = errors.New("login failed")
	return err
}

func Login(target, domain, username, password string) error {
	var err error
	g := NewClient(target, glog.NONE)
	// SSL login test
	err = g.loginForSSL(domain, username, password)
	if err == nil {
		return nil
	}
	if err.Error() != PROTOCOL_RDP {
		return err
	}
	// RDP login test
	err = g.loginForRDP(domain, username, password)
	if err == nil {
		return nil
	} else {
		return err
	}
}

func LoginForSSL(target, domain, username, password string) error {
	var err error
	g := NewClient(target, glog.NONE)
	// SSL login test
	err = g.loginForSSL(domain, username, password)
	if err == nil {
		return nil
	}
	return err
}

func LoginForRDP(target, domain, username, password string) error {
	var err error
	g := NewClient(target, glog.NONE)
	// SSL login test
	err = g.loginForRDP(domain, username, password)
	if err == nil {
		return nil
	}
	return err
}

func VerifyProtocol(target string) string {
	var err error
	err = LoginForSSL(target, "", "administrator", "test")
	if err == nil {
		return PROTOCOL_SSL
	}
	if err.Error() != PROTOCOL_RDP {
		return PROTOCOL_SSL
	}
	return PROTOCOL_RDP
}
