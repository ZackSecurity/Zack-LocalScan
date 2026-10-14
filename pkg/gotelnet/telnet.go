// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package gotelnet

import (
	"Zack-LocalScan/pkg/slog"
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Timeout is the connection timeout for Telnet dial. Hardcoded 3s — dial only; login process has its own staged delays.
var Timeout = 3 * time.Second

const (
	TIME_DELAY_AFTER_WRITE = 300 * time.Millisecond

	// Telnet protocol characters (don't change)
	IAC  = byte(255) // "Interpret As Command"
	DONT = byte(254)
	DO   = byte(253)
	WONT = byte(252)
	WILL = byte(251)
	SB   = byte(250) // Subnegotiation Begin
	SE   = byte(240) // Subnegotiation End

	NULL  = byte(0)
	EOF   = byte(236) // Document End
	SUSP  = byte(237) // Subnegotiation End
	ABORT = byte(238) // Process Stop
	REOR  = byte(239) // Record End
	NOP   = byte(241) // No Operation
	DM    = byte(242) // Data Mark
	BRK   = byte(243) // Break
	IP    = byte(244) // Interrupt process
	AO    = byte(245) // Abort output
	AYT   = byte(246) // Are You There
	EC    = byte(247) // Erase Character
	EL    = byte(248) // Erase Line
	GA    = byte(249) // Go Ahead

	// Telnet protocol options code (don't change)
	// These ones all come from arpa/telnet.h
	BINARY         = byte(0)  // 8-bit data path
	ECHO           = byte(1)  // echo
	RCP            = byte(2)  // prepare to reconnect
	SGA            = byte(3)  // suppress go ahead
	NAMS           = byte(4)  // approximate message size
	STATUS         = byte(5)  // give status
	TM             = byte(6)  // timing mark
	RCTE           = byte(7)  // remote controlled transmission and echo
	NAOL           = byte(8)  // negotiate about output line width
	NAOP           = byte(9)  // negotiate about output page size
	NAOCRD         = byte(10) // negotiate about CR disposition
	NAOHTS         = byte(11) // negotiate about horizontal tabstops
	NAOHTD         = byte(12) // negotiate about horizontal tab disposition
	NAOFFD         = byte(13) // negotiate about formfeed disposition
	NAOVTS         = byte(14) // negotiate about vertical tab stops
	NAOVTD         = byte(15) // negotiate about vertical tab disposition
	NAOLFD         = byte(16) // negotiate about output LF disposition
	XASCII         = byte(17) // extended ascii character set
	LOGOUT         = byte(18) // force logout
	BM             = byte(19) // byte macro
	DET            = byte(20) // data entry terminal
	SUPDUP         = byte(21) // supdup protocol
	SUPDUPOUTPUT   = byte(22) // supdup output
	SNDLOC         = byte(23) // send location
	TTYPE          = byte(24) // terminal type
	EOR            = byte(25) // end or record
	TUID           = byte(26) // TACACS user identification
	OUTMRK         = byte(27) // output marking
	TTYLOC         = byte(28) // terminal location number
	VT3270REGIME   = byte(29) // 3270 regime
	X3PAD          = byte(30) // X.3 PAD
	NAWS           = byte(31) // window size
	TSPEED         = byte(32) // terminal speed
	LFLOW          = byte(33) // remote flow control
	LINEMODE       = byte(34) // Linemode option
	XDISPLOC       = byte(35) // X Display Location
	OLD_ENVIRON    = byte(36) // Old - Environment variables
	AUTHENTICATION = byte(37) // Authenticate
	ENCRYPT        = byte(38) // Encryption option
	NEW_ENVIRON    = byte(39) // New - Environment variables
	// the following ones come from
	// http://www.iana.org/assignments/telnet-options
	// Unfortunately, that document does not assign identifiers
	// to all of them, so we are making them up
	TN3270E             = byte(40)  // TN3270E
	XAUTH               = byte(41)  // XAUTH
	CHARSET             = byte(42)  // CHARSET
	RSP                 = byte(43)  // Telnet Remote Serial Port
	COM_PORT_OPTION     = byte(44)  // Com Port Control Option
	SUPPRESS_LOCAL_ECHO = byte(45)  // Telnet Suppress Local Echo
	TLS                 = byte(46)  // Telnet Start TLS
	KERMIT              = byte(47)  // KERMIT
	SEND_URL            = byte(48)  // SEND-URL
	FORWARD_X           = byte(49)  // FORWARD_X
	PRAGMA_LOGON        = byte(138) // TELOPT PRAGMA LOGON
	SSPI_LOGON          = byte(139) // TELOPT SSPI LOGON
	PRAGMA_HEARTBEAT    = byte(140) // TELOPT PRAGMA HEARTBEAT
	EXOPL               = byte(255) // Extended-Options-List
	NOOPT               = byte(0)
)

const (
	Closed = iota
	UnauthorizedAccess
	OnlyPassword
	UsernameAndPassword
)

type Client struct {
	IPAddr       string
	Port         int
	UserName     string
	Password     string
	conn         net.Conn
	LastResponse string
	ServerType   int
}

func New(addr string, port int) *Client {
	return &Client{
		IPAddr:       addr,
		Port:         port,
		UserName:     "",
		Password:     "",
		conn:         nil,
		LastResponse: "",
		ServerType:   0,
	}
}

func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.Netloc(), Timeout)
	if err != nil {
		return err
	}
	c.conn = conn
	// start reading incoming data
	go func() {
		for {
			buf, err := c.read()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					break
				}
				if strings.Contains(err.Error(), "EOF") {
					break
				}
				//slog.Printf(slog.WARN, "%v:%v,telnet read is err:%v,", c.IPAddr, c.Port, err)
				break
			}
			displayBuf, commandList := c.SerializationResponse(buf)
			if len(commandList) > 0 {
				replyBuf := c.MakeReplyFromList(commandList)
				c.LastResponse += string(displayBuf)
				_ = c.write(replyBuf)
			} else {
				c.LastResponse += string(displayBuf)
			}
		}
	}()
	// wait for initialization
	time.Sleep(time.Second * 3)
	return nil
}

func (c *Client) WriteContext(s string) {
	_ = c.write([]byte(s + "\x0d\x00"))
}

func (c *Client) ReadContext() string {
	defer func() { c.Clear() }() // clear buffered output when done
	if c.LastResponse == "" {
		time.Sleep(time.Second)
	}
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x00", "")
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x0a", "\n")
	//c.LastResponse = chinese.ToUTF8(c.LastResponse)
	return c.LastResponse
}

func (c *Client) Netloc() string {
	return fmt.Sprintf("%s:%d", c.IPAddr, c.Port)
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) SerializationResponse(responseBuf []byte) (displayBuf []byte, commandList [][]byte) {
	for {
		index := bytes.IndexByte(responseBuf, IAC)
		if index == -1 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}
		if len(responseBuf)-index < 2 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}
		// option byte
		ch := responseBuf[index+1]
		if ch == IAC {
			// text before the IAC goes to the display buffer
			displayBuf = append(displayBuf, responseBuf[:index]...)
			// drop the processed prefix
			responseBuf = responseBuf[index+1:]
			continue
		}
		if ch == DO || ch == DONT || ch == WILL || ch == WONT {
			if index+3 > len(responseBuf) {
				// chunk ends with an incomplete negotiation command; drop the tail
				displayBuf = append(displayBuf, responseBuf[:index]...)
				break
			}
			IACBuf := responseBuf[index : index+3]
			// store the whole 3-byte IAC command
			commandList = append(commandList, IACBuf)
			// text before the IAC goes to the display buffer
			displayBuf = append(displayBuf, responseBuf[:index]...)
			// drop the processed prefix
			responseBuf = responseBuf[index+3:]
			continue
		}
		if ch == SB {
			// text before the IAC goes to the display buffer
			displayBuf = append(displayBuf, responseBuf[:index]...)
			// find SE after the SB; if it is missing, the subnegotiation is incomplete in this
			// chunk - drop the tail instead of slicing out of bounds
			seIndex := bytes.IndexByte(responseBuf[index+2:], SE)
			if seIndex == -1 {
				break
			}
			seIndex += index + 2
			// store the IAC SB .. SE subnegotiation
			commandList = append(commandList, responseBuf[index:seIndex])
			// drop the processed prefix
			responseBuf = responseBuf[seIndex+1:]
			continue
		}
		break
	}
	return displayBuf, commandList
}

func (c *Client) MakeReplyFromList(list [][]byte) []byte {
	var reply []byte
	for _, command := range list {
		reply = append(reply, c.MakeReply(command)...)
	}
	return reply
}

func (c *Client) MakeReply(command []byte) []byte {
	if len(command) < 3 {
		return []byte{}
	}
	verb := command[1]
	option := command[2]
	// SB commands also read a 4th byte (the modifier); ignore short ones instead of panicking.
	if verb == SB && len(command) < 4 {
		return []byte{}
	}

	// option is ECHO (1) or SGA (3)
	if option == ECHO {
		if verb == DO {
			return []byte{IAC, WILL, option}
		}
		if verb == DONT {
			return []byte{IAC, WONT, option}
		}
		if verb == WILL {
			return []byte{IAC, DO, option}
		}
		if verb == WONT {
			return []byte{IAC, DONT, option}
		}
		if verb == SB {
			/*
			 * subnegotiation extends the command to 4 bytes;
			 * the last byte is the option code.
			 * if that option byte is 1 (SEND), reply with
			 * 250 (SB) + option + 0 (IS) + 255 (IAC) + 240 (SE)
			 */
			modifier := command[3]
			if modifier == ECHO {
				return []byte{IAC, SB, option, BINARY, IAC, SE}
			}
		}
	} else if option == SGA {
		if verb == DO {
			return []byte{IAC, WILL, option}
		}
		if verb == DONT {
			return []byte{IAC, WONT, option}
		}
		if verb == WILL {
			return []byte{IAC, DO, option}
		}
		if verb == WONT {
			return []byte{IAC, DONT, option}
		}
		if verb == SB {
			/*
			 * subnegotiation extends the command to 4 bytes;
			 * the last byte is the option code.
			 * if that option byte is 1 (SEND), reply with
			 * 250 (SB) + option + 0 (IS) + 255 (IAC) + 240 (SE)
			 */
			modifier := command[3]
			if modifier == ECHO {
				return []byte{IAC, SB, option, BINARY, IAC, SE}
			}
		}
	} else {
		if verb == DO {
			return []byte{IAC, WONT, option}
		}
		if verb == DONT {
			return []byte{IAC, WONT, option}
		}
		if verb == WILL {
			return []byte{IAC, DONT, option}
		}
		if verb == WONT {
			return []byte{IAC, DONT, option}
		}
	}
	return []byte{}
}

func (c *Client) read() ([]byte, error) {
	var buf [2048]byte
	var n int
	_ = c.conn.SetReadDeadline(time.Now().Add(Timeout))
	n, err := c.conn.Read(buf[0:])
	if err != nil {
		return nil, err
	}
	//slog.Println(slog.DEBUG, buf[:n], "-<<<<<<<<")
	return buf[:n], nil
}

func (c *Client) write(buf []byte) error {
	//slog.Println(slog.DEBUG, ">>>>>>>>>-", buf)
	_ = c.conn.SetWriteDeadline(time.Now().Add(Timeout))
	_, err := c.conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Login() error {
	switch c.ServerType {
	case Closed:
		return errors.New("service is disabled")
	case UnauthorizedAccess:
		return nil
	case OnlyPassword:
		return c.loginForOnlyPassword()
	case UsernameAndPassword:
		return c.loginForUsernameAndPassword()
	}
	return errors.New("unknown server type")
}

func (c *Client) MakeServerType() int {
	responseString := c.ReadContext()
	response := strings.Split(responseString, "\n")
	lastLine := response[len(response)-1]
	lastLine = strings.ToLower(lastLine)
	if strings.Contains(lastLine, "user") || strings.Contains(lastLine, "name") || strings.Contains(lastLine, "login") || strings.Contains(lastLine, "account") || strings.Contains(lastLine, "用户名") || strings.Contains(lastLine, "登录") {
		//slog.Printf(slog.INFO, "%v:%v,telnet mode is : usernameAndPassword ,response is :%v", c.IPAddr, c.Port, lastLine)
		return UsernameAndPassword
	}
	if strings.Contains(lastLine, "pass") {
		//slog.Printf(slog.INFO, "%v:%v,telnet mode is : onlyPassword ,response is :%v", c.IPAddr, c.Port, lastLine)
		return OnlyPassword
	}
	if regexp.MustCompile(`^/ #.*`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if regexp.MustCompile(`^<[A-Za-z0-9_]+>`).MatchString(lastLine) {
		return UnauthorizedAccess
	}
	if regexp.MustCompile(`^#`).MatchString(lastLine) {
		return UnauthorizedAccess
	}

	if c.isLoginSucceed(responseString) {
		return UnauthorizedAccess
	}

	slog.Printf(slog.WARN, "%v:%v, unknown Telnet mode, response: %v", c.IPAddr, c.Port, lastLine)
	return Closed
}

func (c *Client) loginForOnlyPassword() error {
	c.Clear()
	// clear the buffered output
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 3)

	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}

	if c.isLoginSucceed(responseString) {
		return nil
	}

	//slog.Println(slog.WARN, c.IPAddr, c.Port, "|", responseString)
	return errors.New("login failed")

}

func (c *Client) loginForUsernameAndPassword() error {
	c.WriteContext(c.UserName)
	time.Sleep(time.Second * 3)
	c.Clear() // clear the buffered output
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 5)

	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}
	//slog.Println(slog.WARN, c.IPAddr, c.Port, "|", responseString)
	return errors.New("login failed")
}

func (c *Client) Clear() {
	c.LastResponse = ""
}

var loginFailedString = []string{
	"wrong",
	"invalid",
	"fail",
	"incorrect",
	"error",
}

var (
	rePassPrompt   = regexp.MustCompile("(?is).*pass(word)?:$")
	reUserPrompt   = regexp.MustCompile("(?is).*user(name)?:$")
	reLoginPrompt  = regexp.MustCompile("(?is).*login:$")
	reShellPrompt  = regexp.MustCompile("^[#$].*")
	reDevicePrompt = regexp.MustCompile("^<[a-zA-Z0-9_]+>.*")
	reLastLogin    = regexp.MustCompile("(?:s)last login")
)

func (c *Client) isLoginFailed(responseString string) bool {
	responseString = strings.ToLower(responseString)
	if responseString == "" {
		return true
	}
	for _, str := range loginFailedString {
		if strings.Contains(responseString, str) {
			return true
		}
	}
	if rePassPrompt.MatchString(responseString) {
		return true
	}
	if reUserPrompt.MatchString(responseString) {
		return true
	}
	if reLoginPrompt.MatchString(responseString) {
		return true
	}
	return false
}

func (c *Client) isLoginSucceed(responseString string) bool {
	responseStringArray := strings.Split(responseString, "\n")
	lastLine := responseStringArray[len(responseStringArray)-1]
	if reShellPrompt.MatchString(lastLine) {
		return true
	}
	if reDevicePrompt.MatchString(lastLine) {
		return true
	}
	if reLastLogin.MatchString(responseString) {
		return true
	}
	c.Clear()
	c.WriteContext("?")
	time.Sleep(time.Second * 3)
	responseString = c.ReadContext()
	if strings.Count(responseString, "\n") > 6 {
		return true
	}
	if len([]rune(responseString)) > 100 {
		return true
	}
	return false
}
