package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"goPSLoginServer/utils/config"
	"goPSLoginServer/utils/logging"
)

const (
	connectionURI = "postgres://%s:%s@%s:%d/%s"
)

// local object
var loginServerDB *Database

type Database struct {
	dbpool *pgxpool.Pool

	Host string
	Port uint16

	Username string
	Password string
	Database string
}

// Init
//
// Used in main to initialize the login server database connection.
// Errors will lead to a fatal error.
func Init() {

	var (
		err error

		db *Database

		dbconf = config.GetInstance().Database
	)

	db = &Database{
		Host:     dbconf.Host,
		Port:     dbconf.Port,
		Username: dbconf.User,
		Password: dbconf.Password,
		Database: dbconf.Database,
	}

	err = db.init()
	if err != nil {
		log.Fatalf("Faied to connect to database: %v", err)
	}

	loginServerDB = db

	return
}

// GetInstance
//
// Returns the singleton loginServerDB object of the login server database
func GetInstance() *Database {

	return loginServerDB
}

// New
//
// Used in the code to connect to additional databases.
// For example to connect to world server databases.
func New(host string, port uint16, username string, password string, dbname string) (db *Database, err error) {

	db = &Database{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		Database: dbname,
	}

	err = db.init()
	if err != nil {
		err = fmt.Errorf(
			"DB init failed: %v",
			err,
		)

		return
	}

	return
}

// init
//
// Constructs the connection URI and tries to establish a connection to the Database
func (db *Database) init() (err error) {

	var (
		connURI = fmt.Sprintf(
			connectionURI,
			db.Username,
			db.Password,
			db.Host,
			db.Port,
			db.Database,
		)
	)

	db.dbpool, err = pgxpool.New(context.Background(), connURI)
	if err != nil {
		return fmt.Errorf(
			"Failed to establish connection to DB %s:%d as %s on %s: %v",
			db.Host,
			db.Port,
			db.Username,
			db.Database,
			err,
		)
	}

	return
}

func (db *Database) GetConnection() (conn *pgxpool.Conn, err error) {

	return db.acquireConnection(5)
}

func (db *Database) acquireConnection(attemptsLeft int) (conn *pgxpool.Conn, err error) {

	attemptsLeft -= 1

	conn, err = db.dbpool.Acquire(context.Background())
	if err != nil {
		logging.Debugf("Failed to acquire a DB connection with %d attempts left: %v", attemptsLeft, err)

		// if there are attempts left, retry
		if attemptsLeft > 0 {
			// sleep a temporary network problem away
			time.Sleep(5)
			// recursively call this function with one less attempt left
			return db.acquireConnection(attemptsLeft)
		}

		// no attempts left, return an error
		return nil, fmt.Errorf("Finally failed to acquire a DB connection: %v", err)
	}

	// got the connection
	return
}

func (db *Database) Execute(
	ctx context.Context,
	query string,
	params ...any,
) (tag pgconn.CommandTag, err error) {

	var (
		conn *pgxpool.Conn
	)

	conn, err = db.GetConnection()
	if err != nil {
		logging.Debugf("Failed Execute query: %v", err)
		return
	}
	defer conn.Release()

	tag, err = conn.Exec(ctx, query, params...)

	return
}

func (db *Database) Query(
	ctx context.Context,
	query string,
	params ...any,
) (rows pgx.Rows, err error) {

	var (
		conn *pgxpool.Conn
	)

	conn, err = db.GetConnection()
	if err != nil {
		logging.Debugf("Failed Query query: %v", err)
		return
	}
	defer conn.Release()

	rows, err = conn.Query(ctx, query, params...)

	// if len(params) != 0 {
	// 	rows, err = conn.Query(ctx, query, params)
	// } else {
	// 	rows, err = conn.Query(ctx, query)
	// }

	return
}

func (db *Database) QueryRow(
	ctx context.Context,
	query string,
	params ...any,
) (row pgx.Row, err error) {

	var (
		conn *pgxpool.Conn
	)

	conn, err = db.GetConnection()
	if err != nil {
		logging.Debugf("Failed QueryRow query: %v", err)
		return
	}
	defer conn.Release()

	row = conn.QueryRow(ctx, query, params...)

	return
}

func (db *Database) Close() {

	db.dbpool.Close()
}
