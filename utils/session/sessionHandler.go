package session

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

func (sh *sessionHandler) GetOrCreateSession(clientEndpoint uint32, isClientStartup bool) *Session {

	var (
		newSession *Session

		session, ok = sh.sessions[clientEndpoint]
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
	sh.sessions[clientEndpoint] = newSession

	return newSession
}
