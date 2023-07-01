package session

import (
	"encoding/binary"
	"net"
)

type sessionHandler struct {
	sessions map[uint32]*Session
}

var instance *sessionHandler

func GetSessionHandler() *sessionHandler {
	if instance == nil {
		instance = &sessionHandler{
			sessions: make(map[uint32]*Session),
		}
	}

	return instance
}

func (sh *sessionHandler) GetOrCreateSession(clientEndpoint *net.UDPAddr, isClientStartup bool) *Session {

	var (
		newSession *Session

		hash        = binary.LittleEndian.Uint32(clientEndpoint.IP)
		session, ok = sh.sessions[hash]
	)

	// if session exists return it
	if ok {
		return session
	}

	// only allow new sessions for ClientStartup packets
	if !isClientStartup {
		return nil
	}

	// session does not exist, create it
	newSession = NewSession(clientEndpoint)

	// add session to session handler
	sh.sessions[hash] = newSession

	return newSession
}

func (sh *sessionHandler) RemoveSession(sess *Session) {

	var (
		hash = binary.LittleEndian.Uint32(sess.ClientEndpoint.IP)
	)

	delete(sh.sessions, hash)
}
