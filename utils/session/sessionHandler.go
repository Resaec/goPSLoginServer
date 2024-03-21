package session

import (
	"fmt"
	"hash/fnv"
	"net"

	"goPSLoginServer/utils/logging"
)

type sessionHandler struct {
	sessions map[uint32]*Session
}

var instance *sessionHandler

func GetSessionHandler() *sessionHandler {

	if instance != nil {
		return instance
	}

	instance = &sessionHandler{
		sessions: make(map[uint32]*Session),
	}

	return instance
}

func (sh *sessionHandler) GetOrCreateSession(clientEndpoint *net.UDPAddr, isClientStartup bool) *Session {

	var (
		newSession *Session

		hash        = sh.getSessionHashForEndpoint(clientEndpoint)
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
		hash = sh.getSessionHashForEndpoint(sess.ClientEndpoint)
	)

	delete(sh.sessions, hash)
}

func (sh *sessionHandler) getSessionHashForEndpoint(clientEndpoint *net.UDPAddr) (hash uint32) {

	var (
		err error

		hasher = fnv.New32a() // should be fiiinnneee

		key = fmt.Sprintf("%s:%d", clientEndpoint.IP, clientEndpoint.Port)
	)

	_, err = hasher.Write([]byte(key))
	if err != nil {
		logging.Errf("Failed to hash client endpoint: %v", err)
		return
	}

	hash = hasher.Sum32()

	return
}
