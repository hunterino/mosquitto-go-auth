package backends

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//Postgres holds all fields of the postgres db connection.
type Postgres struct {
	pool              *pgxpool.Pool
	Host              string
	Port              string
	DBName            string
	User              string
	Password          string
	UserQuery         string
	SuperuserQuery    string
	AclQuery          string
	SSLMode           string
	SSLCert           string
	SSLKey            string
	SSLRootCert       string
	hasher            hashing.HashComparer
	maxLifeTime       int64
	maxConnections    int32
	minConnections    int32
	maxConnIdleTime   time.Duration
	healthCheckPeriod time.Duration
	connectTries      int

	// Prepared statements
	usePreparedStmts     bool
	userStmtName         string
	superuserStmtName    string
	aclStmtName          string
	preparedStmtsReady   bool
}

func NewPostgres(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (Postgres, error) {

	log.SetLevel(logLevel)

	//Set defaults for postgres

	pgOk := true
	missingOptions := ""

	var postgres = Postgres{
		Host:              "localhost",
		Port:              "5432",
		SSLMode:           "verify-full",
		SuperuserQuery:    "",
		AclQuery:          "",
		hasher:            hasher,
		maxConnections:    25,
		minConnections:    5,
		maxConnIdleTime:   time.Duration(300) * time.Second,
		healthCheckPeriod: time.Duration(60) * time.Second,
	}

	if host, ok := authOpts["pg_host"]; ok {
		postgres.Host = host
	}

	if port, ok := authOpts["pg_port"]; ok {
		postgres.Port = port
	}

	if dbName, ok := authOpts["pg_dbname"]; ok {
		postgres.DBName = dbName
	} else {
		pgOk = false
		missingOptions += " pg_dbname"
	}

	if user, ok := authOpts["pg_user"]; ok {
		postgres.User = user
	} else {
		pgOk = false
		missingOptions += " pg_user"
	}

	if password, ok := authOpts["pg_password"]; ok {
		postgres.Password = password
	} else {
		pgOk = false
		missingOptions += " pg_password"
	}

	if userQuery, ok := authOpts["pg_userquery"]; ok {
		postgres.UserQuery = userQuery
	} else {
		pgOk = false
		missingOptions += " pg_userquery"
	}

	if superuserQuery, ok := authOpts["pg_superquery"]; ok {
		postgres.SuperuserQuery = superuserQuery
	}

	if aclQuery, ok := authOpts["pg_aclquery"]; ok {
		postgres.AclQuery = aclQuery
	}

	if sslmode, ok := authOpts["pg_sslmode"]; ok {
		switch sslmode {
		case "verify-full", "verify-ca", "require", "disable":
		default:
			log.Warnf("PG backend warning: using unknown pg_sslmode: '%s'", sslmode)
		}
		postgres.SSLMode = sslmode
	} else {
		postgres.SSLMode = "verify-full"
	}

	if sslCert, ok := authOpts["pg_sslcert"]; ok {
		postgres.SSLCert = sslCert
	}

	if sslKey, ok := authOpts["pg_sslkey"]; ok {
		postgres.SSLKey = sslKey
	}

	if sslRootCert, ok := authOpts["pg_sslrootcert"]; ok {
		postgres.SSLRootCert = sslRootCert
	}

	//Exit if any mandatory option is missing.
	if !pgOk {
		return postgres, errors.Errorf("PG backend error: missing options: %s", missingOptions)
	}

	//Build the dsn string and try to connect to the db.
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s", postgres.User, postgres.Password, postgres.DBName, postgres.Host, postgres.Port)

	switch postgres.SSLMode {
	case "disable":
		connStr = fmt.Sprintf("%s sslmode=disable", connStr)
	case "require":
		connStr = fmt.Sprintf("%s sslmode=require", connStr)
	case "verify-ca":
		connStr = fmt.Sprintf("%s sslmode=verify-ca", connStr)
	case "verify-full":
		fallthrough
	default:
		connStr = fmt.Sprintf("%s sslmode=verify-full", connStr)
	}

	if postgres.SSLRootCert != "" {
		connStr = fmt.Sprintf("%s sslrootcert=%s", connStr, postgres.SSLRootCert)
	}

	if postgres.SSLKey != "" {
		connStr = fmt.Sprintf("%s sslkey=%s", connStr, postgres.SSLKey)
	}

	if postgres.SSLCert != "" {
		connStr = fmt.Sprintf("%s sslcert=%s", connStr, postgres.SSLCert)
	}

	if tries, ok := authOpts["pg_connect_tries"]; ok {
		connectTries, err := strconv.Atoi(tries)

		if err != nil {
			log.Warnf("invalid postgres connect tries options: %s", err)
		} else {
			postgres.connectTries = connectTries
		}
	}

	if maxLifeTime, ok := authOpts["pg_max_life_time"]; ok {
		lifeTime, err := strconv.ParseInt(maxLifeTime, 10, 64)

		if err == nil {
			postgres.maxLifeTime = lifeTime
		}
	}

	// Parse connection pool configuration
	if maxConns, ok := authOpts["pg_max_connections"]; ok {
		if val, err := strconv.ParseInt(maxConns, 10, 32); err == nil {
			postgres.maxConnections = int32(val)
		} else {
			log.Warnf("invalid pg_max_connections value: %s", err)
		}
	}

	if minConns, ok := authOpts["pg_min_connections"]; ok {
		if val, err := strconv.ParseInt(minConns, 10, 32); err == nil {
			postgres.minConnections = int32(val)
		} else {
			log.Warnf("invalid pg_min_connections value: %s", err)
		}
	}

	if maxIdleTime, ok := authOpts["pg_max_conn_idle_time"]; ok {
		if val, err := strconv.ParseInt(maxIdleTime, 10, 64); err == nil {
			postgres.maxConnIdleTime = time.Duration(val) * time.Second
		} else {
			log.Warnf("invalid pg_max_conn_idle_time value: %s", err)
		}
	}

	if healthPeriod, ok := authOpts["pg_health_check_period"]; ok {
		if val, err := strconv.ParseInt(healthPeriod, 10, 64); err == nil {
			postgres.healthCheckPeriod = time.Duration(val) * time.Second
		} else {
			log.Warnf("invalid pg_health_check_period value: %s", err)
		}
	}

	// Parse prepared statements configuration (enabled by default for performance)
	postgres.usePreparedStmts = true
	if prepStmts, ok := authOpts["pg_use_prepared_statements"]; ok {
		if prepStmts == "false" {
			postgres.usePreparedStmts = false
		}
	}

	// Set prepared statement names if enabled
	if postgres.usePreparedStmts {
		postgres.userStmtName = "pg_get_user"
		postgres.superuserStmtName = "pg_get_superuser"
		postgres.aclStmtName = "pg_check_acl"
	}

	// Parse the connection string into pgx config
	ctx := context.Background()
	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return postgres, errors.Errorf("PG backend error: couldn't parse connection string: %s", err)
	}

	// Configure connection pool
	poolConfig.MaxConns = postgres.maxConnections
	poolConfig.MinConns = postgres.minConnections
	poolConfig.MaxConnIdleTime = postgres.maxConnIdleTime
	poolConfig.HealthCheckPeriod = postgres.healthCheckPeriod

	if postgres.maxLifeTime > 0 {
		poolConfig.MaxConnLifetime = time.Duration(postgres.maxLifeTime) * time.Second
	}

	// Create the connection pool with retries
	var pool *pgxpool.Pool
	maxTries := postgres.connectTries
	if maxTries == 0 {
		maxTries = 1
	}

	for i := 0; i < maxTries; i++ {
		pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
		if err == nil {
			// Test the connection
			err = pool.Ping(ctx)
			if err == nil {
				break
			}
			pool.Close()
		}

		if i < maxTries-1 {
			log.Warnf("PG backend: connection attempt %d failed: %s, retrying...", i+1, err)
			time.Sleep(time.Second * 2)
		}
	}

	if err != nil {
		return postgres, errors.Errorf("PG backend error: couldn't connect to database after %d tries: %s", maxTries, err)
	}

	postgres.pool = pool
	log.Infof("PG backend: connected successfully with pool (max: %d, min: %d)", postgres.maxConnections, postgres.minConnections)

	// Prepare statements if enabled
	if postgres.usePreparedStmts {
		err = postgres.prepareStatements(ctx)
		if err != nil {
			log.Warnf("PG backend: failed to prepare statements, falling back to non-prepared mode: %s", err)
			postgres.usePreparedStmts = false
			postgres.preparedStmtsReady = false
		} else {
			postgres.preparedStmtsReady = true
			log.Info("PG backend: prepared statements created successfully")
		}
	}

	return postgres, nil

}

// prepareStatements creates prepared statements for all queries
func (o *Postgres) prepareStatements(ctx context.Context) error {
	conn, err := o.pool.Acquire(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to acquire connection for preparing statements")
	}
	defer conn.Release()

	// Prepare user query statement
	if o.UserQuery != "" {
		_, err = conn.Conn().Prepare(ctx, o.userStmtName, o.UserQuery)
		if err != nil {
			return errors.Wrapf(err, "failed to prepare user statement: %s", o.UserQuery)
		}
		log.Debugf("PG backend: prepared user statement '%s'", o.userStmtName)
	}

	// Prepare superuser query statement (if configured)
	if o.SuperuserQuery != "" {
		_, err = conn.Conn().Prepare(ctx, o.superuserStmtName, o.SuperuserQuery)
		if err != nil {
			return errors.Wrapf(err, "failed to prepare superuser statement: %s", o.SuperuserQuery)
		}
		log.Debugf("PG backend: prepared superuser statement '%s'", o.superuserStmtName)
	}

	// Prepare ACL query statement (if configured)
	if o.AclQuery != "" {
		_, err = conn.Conn().Prepare(ctx, o.aclStmtName, o.AclQuery)
		if err != nil {
			return errors.Wrapf(err, "failed to prepare ACL statement: %s", o.AclQuery)
		}
		log.Debugf("PG backend: prepared ACL statement '%s'", o.aclStmtName)
	}

	return nil
}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Postgres) GetUser(username, password, clientid string) (bool, error) {
	ctx := context.Background()

	var pwHash string
	var err error

	// Use prepared statement if available, otherwise use regular query
	if o.preparedStmtsReady {
		err = o.pool.QueryRow(ctx, o.userStmtName, username).Scan(&pwHash)
	} else {
		err = o.pool.QueryRow(ctx, o.UserQuery, username).Scan(&pwHash)
	}

	if err != nil {
		if err == pgx.ErrNoRows {
			// avoid leaking the fact that user exists or not through error.
			return false, nil
		}

		log.Debugf("PG get user error: %s", err)
		return false, err
	}

	if pwHash == "" {
		log.Debugf("PG get user error: user %s has empty password hash", username)
		return false, nil
	}

	if o.hasher.Compare(password, pwHash) {
		return true, nil
	}

	return false, nil

}

//GetSuperuser checks that the username meets the superuser query.
func (o Postgres) GetSuperuser(username string) (bool, error) {

	//If there's no superuser query, return false.
	if o.SuperuserQuery == "" {
		return false, nil
	}

	ctx := context.Background()

	var count int64
	var err error

	// Use prepared statement if available, otherwise use regular query
	if o.preparedStmtsReady {
		err = o.pool.QueryRow(ctx, o.superuserStmtName, username).Scan(&count)
	} else {
		err = o.pool.QueryRow(ctx, o.SuperuserQuery, username).Scan(&count)
	}

	if err != nil {
		if err == pgx.ErrNoRows {
			// avoid leaking the fact that user exists or not through error.
			return false, nil
		}

		log.Debugf("PG get superuser error: %s", err)
		return false, err
	}

	if count > 0 {
		return true, nil
	}

	return false, nil

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Postgres) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	//If there's no acl query, assume all privileges for all users.
	if o.AclQuery == "" {
		return true, nil
	}

	ctx := context.Background()

	var rows pgx.Rows
	var err error

	// Use prepared statement if available, otherwise use regular query
	if o.preparedStmtsReady {
		rows, err = o.pool.Query(ctx, o.aclStmtName, username, acc)
	} else {
		rows, err = o.pool.Query(ctx, o.AclQuery, username, acc)
	}

	if err != nil {
		log.Debugf("PG check acl error: %s", err)
		return false, err
	}
	defer rows.Close()

	var acls []string
	for rows.Next() {
		var acl string
		if err := rows.Scan(&acl); err != nil {
			log.Debugf("PG check acl scan error: %s", err)
			return false, err
		}
		acls = append(acls, acl)
	}

	if err := rows.Err(); err != nil {
		log.Debugf("PG check acl rows error: %s", err)
		return false, err
	}

	for _, acl := range acls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if topics.Match(aclTopic, topic) {
			return true, nil
		}
	}

	return false, nil

}

//GetName returns the backend's name
func (o Postgres) GetName() string {
	return "Postgres"
}

//Halt closes the postgres connection pool.
func (o Postgres) Halt() {
	if o.pool != nil {
		log.Info("Postgres: closing connection pool")
		o.pool.Close()
	}
}
