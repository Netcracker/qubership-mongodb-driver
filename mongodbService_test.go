// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package driver

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/docker/distribution/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func GetLogger(debug bool) *zap.Logger {
	var atom zap.AtomicLevel
	if debug {
		atom = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	} else {
		atom = zap.NewAtomicLevel()
	}
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		atom,
	))
	defer logger.Sync()
	return logger
}

func GetEnvAsBool(name string, defaultVal bool) bool {
	valueStr := GetEnv(name, "")
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}

	return defaultVal
}

func GetEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultVal
}

func generateUUID() string {
	return uuid.Generate().String()
}

var logger = GetLogger(GetEnvAsBool("DEBUG_LOG", true))
var serverHostname = GetEnv("TEST_MONGO_HOST", "localhost") //10.236.155.207

func WithMongo(t *testing.T) testcontainers.Container {
	if serverHostname != "localhost" {
		return nil
	}
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "artifactorycn.netcracker.com:17064/mongo:7.0.5",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor:   wait.ForExposedPort(),
	}
	mongoC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("Could not start mongodb: %s", err)
	}
	serverHostname, err = mongoC.Endpoint(ctx, "")
	if err != nil {
		t.Error(err)
	}

	return mongoC
}

func prepareMongoDB(t *testing.T) {
	WithMongo(t)
	conf := MongoConfigurationImpl{Hostname: serverHostname}
	ms := MongoServiceImpl{Configuration: &conf, Logger: logger}
	if exists, _ := ms.IsUserExist(context.Background(), ms.Configuration, "dbaas", "admin"); !exists {
		client, err := GetMongoClient(&conf)
		if err != nil {
			panic(err)
		}
		commandResult := client.Database("admin").RunCommand(context.TODO(),
			bson.D{primitive.E{Key: "createUser", Value: "dbaas"},
				primitive.E{Key: "pwd", Value: "dbaas"},
				primitive.E{Key: "roles", Value: []bson.M{
					{"role": "clusterMonitor", "db": "admin"},
					{"role": "userAdminAnyDatabase", "db": "admin"},
					{"role": "readAnyDatabase", "db": "admin"},
				}},
			})

		if commandResult.Err() != nil {
			panic(commandResult.Err())
		}
	}
}

type DBTestSuite struct {
	suite.Suite
	mongoC testcontainers.Container
}

func TestDBTestSuite(t *testing.T) {
	suite.Run(t, new(DBTestSuite))
}

func (s *DBTestSuite) SetupSuite() {
	s.mongoC = WithMongo(s.T())
	prepareMongoDB(s.T())
}

func (s *DBTestSuite) TearDownSuite() {
	if s.mongoC != nil {
		s.mongoC.Terminate(context.Background())
	}
}

func (s *DBTestSuite) TestMongoServiceImpl_ListDatabases() {
	conf := MongoConfigurationImpl{Hostname: serverHostname, AuthDb: "admin", User: "dbaas", Pass: "dbaas"}
	ms := MongoServiceImpl{Configuration: &conf, Logger: logger}

	dbs, err := ms.ListDatabases(context.Background())
	assert.NotEmpty(s.T(), dbs)
	assert.NoError(s.T(), err)
}

func (s *DBTestSuite) TestMongoServiceImpl_Grant_role() {
	conf := MongoConfigurationImpl{Hostname: serverHostname, AuthDb: "admin", User: "dbaas", Pass: "dbaas"}
	ms := MongoServiceImpl{Configuration: &conf, Logger: logger}

	_, err := ms.GrantRole(context.Background(), "foo", dbOwner)
	assert.NoError(s.T(), err)

	_, err = ms.RevokeRole(context.Background(), "foo", dbOwner)
	assert.NoError(s.T(), err)
}

func (s *DBTestSuite) TestMongoServiceImpl_DropDatabase() {
	conf := MongoConfigurationImpl{Hostname: serverHostname, AuthDb: "admin", User: "dbaas", Pass: "dbaas"}
	ms := MongoServiceImpl{Configuration: &conf, Logger: logger}

	dbName := "testDbaas"
	_, err := ms.InsertOne(context.Background(), dbName, "test", bson.D{{"foo", "bar"}})
	assert.NoError(s.T(), err)

	dbs, listErr := ms.ListDatabases(context.Background())
	assert.NoError(s.T(), listErr)
	assert.Contains(s.T(), dbs, dbName)

	err = ms.DropDatabase(context.Background(), dbName)
	assert.NoError(s.T(), err)

	dbs, listErr = ms.ListDatabases(context.Background())
	assert.NoError(s.T(), listErr)
	assert.NotContains(s.T(), dbs, dbName)
}

func (s *DBTestSuite) TestMongoServiceImpl_CreateUser() {
	authDB := "admin"

	conf := MongoConfigurationImpl{Hostname: serverHostname, AuthDb: authDB, User: "dbaas", Pass: "dbaas"}
	ms := MongoServiceImpl{Configuration: &conf, Logger: logger}

	username := generateUUID()
	pass := generateUUID()
	newPass := generateUUID()

	//create user
	err := ms.CreateOrUpdateUser(context.Background(), username, pass, "foo", authDB, "", false, false)
	assert.NoError(s.T(), err)

	//check user's created
	exists, err := ms.IsUserExist(context.Background(), ms.Configuration, username, authDB)
	assert.NoError(s.T(), err)
	assert.True(s.T(), exists)

	//check user can login and execute
	assert.NoError(s.T(), checkUserLogin(authDB, username, pass))

	//change user pass
	err = ms.UpdateUserPassword(context.Background(), username, newPass, authDB)
	assert.NoError(s.T(), err)

	//check user can login and execute
	assert.NoError(s.T(), checkUserLogin(authDB, username, newPass))

	//delete user
	err = ms.DropUser(context.Background(), fmt.Sprintf("%s:%s", authDB, username))
	assert.NoError(s.T(), err)

	//check deleted
	exists, err = ms.IsUserExist(context.Background(), ms.Configuration, username, authDB)
	assert.NoError(s.T(), err)
	assert.False(s.T(), exists)

	//check user cannot execute
	assert.Error(s.T(), checkUserLogin(authDB, username, newPass))
}

func (s *DBTestSuite) TestMongoServiceImpl_CreateRole() {
	authDB := "admin"

	conf := MongoConfigurationImpl{Hostname: serverHostname, AuthDb: authDB, User: "dbaas", Pass: "dbaas"}
	ms := MongoServiceImpl{Configuration: &conf, Logger: logger}

	role := generateUUID()

	//create user
	err := ms.CreateOrUpdateRole(context.Background(), "admin", role, `{"roles": [{"role": "read", "db": "admin"}, {"role": "read", "db": "config"}]}`,
		`{"privileges": [{ "resource": { "db": "", "collection": "" }, "actions": ["find"] }]}`, false)
	assert.NoError(s.T(), err)

	//check role's created
	exists, err := ms.IsRoleExist(context.Background(), ms.Configuration, role, authDB)
	assert.NoError(s.T(), err)
	assert.True(s.T(), exists)
	err = ms.CreateOrUpdateRole(context.Background(), "admin", role, `{"roles":[{"role": "read", "db": "admin"}, {"role": "read", "db": "config"}]}`,
		`{"privileges":[{"resource": { "db": "", "collection": "" }, "actions": ["find", "changeStream"] }]}`, false)
	assert.NoError(s.T(), err)
}

func checkUserLogin(authDB, username, pass string) error {
	newUserConf := MongoConfigurationImpl{Hostname: serverHostname, AuthDb: authDB, User: username, Pass: pass}
	newUserMs := MongoServiceImpl{Configuration: &newUserConf, Logger: logger}
	_, err := newUserMs.ListDatabases(context.Background())
	DisconnectMongoClient(&newUserConf)
	return err
}
