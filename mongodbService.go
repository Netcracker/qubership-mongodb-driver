package driver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const (
	readWrite = "readWrite"
	dbOwner   = "dbOwner"
	streaming = "streaming"
	read      = "read"
)

type MongoService interface {
	RunWithGrants(ctx context.Context, dbName string, ff func(service MongoService) error) error
	CreateOrUpdateUser(ctx context.Context, username, pass, database, authDb, role string, addToShards, force bool) error
	CreateOrUpdateRole(ctx context.Context, authDb, role string, roles, privileges string, addToShards bool) error
	UpdateUserPassword(ctx context.Context, username string, password string, dbName string) error
	IsUserExist(ctx context.Context, conf MongoConfiguration, username string, dbName string) (bool, error)
	DropUser(ctx context.Context, username string) error
	DropDatabase(ctx context.Context, dbName string) error
	ListDatabases(ctx context.Context) ([]string, error)
	InsertOrUpdate(ctx context.Context, dbName string, collection string, data bson.D) (*mongo.UpdateResult, error)
	InsertOne(ctx context.Context, dbName string, collection string, data bson.D) (*mongo.InsertOneResult, error)
	GetOne(ctx context.Context, dbName string, collection string) (*mongo.SingleResult, error)
	GetRoles(ctx context.Context, dbName string) ([]string, error)
	GetDbOwner(ctx context.Context, dbName string) (string, error)
	GrantRoleToUser(ctx context.Context, dbName, user, role string) (*mongo.SingleResult, error)
	GetReplicaSetHosts() ([]string, error)
}

type MongoServiceImpl struct {
	Logger        *zap.Logger
	Configuration MongoConfiguration
}

var _ MongoService = &MongoServiceImpl{}

func (r *MongoServiceImpl) RunWithGrants(ctx context.Context, dbName string, ff func(service MongoService) error) (err error) {
	result, err := r.GrantRole(ctx, dbName, dbOwner)
	if err != nil {
		return err
	} else if result != nil && result.Err() != nil {
		return result.Err()
	}

	defer func() {
		result, err = r.RevokeRole(ctx, dbName, dbOwner)
		if result != nil && result.Err() != nil {
			err = result.Err()
		}
	}()

	return ff(r)
}

func (r *MongoServiceImpl) GrantRoleToUser(ctx context.Context, dbName, user, role string) (*mongo.SingleResult, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	return client.Database(r.Configuration.GetAuthDb()).RunCommand(ctx,
		bson.D{primitive.E{Key: "grantRolesToUser", Value: user},
			primitive.E{Key: "roles", Value: []bson.M{{"role": role, "db": dbName}}}}), nil

}

func (r *MongoServiceImpl) GrantRole(ctx context.Context, dbName, role string) (*mongo.SingleResult, error) {

	return r.GrantRoleToUser(ctx, dbName, r.Configuration.GetUser(), role)
}

func (r *MongoServiceImpl) RevokeRole(ctx context.Context, dbName, role string) (*mongo.SingleResult, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}

	return client.Database(r.Configuration.GetAuthDb()).RunCommand(ctx,
		bson.D{primitive.E{Key: "revokeRolesFromUser", Value: r.Configuration.GetUser()},
			primitive.E{Key: "roles", Value: []bson.M{{"role": role, "db": dbName}}}}), nil

}

func (r *MongoServiceImpl) runCreateOrUpdateRole(ctx context.Context, conf MongoConfiguration,
	authDb, role string, roles, privileges string) error {

	logger := AddLoggerContext(r.Logger, ctx)
	logger.Debug(fmt.Sprintf("check role %v exists on ", role))
	exists, err := r.IsRoleExist(ctx, conf, role, authDb)
	if err != nil {
		return err
	}
	roleCommand := "createRole"
	if exists {
		roleCommand = "updateRole"
	}

	client, err := GetMongoClient(conf)
	if err != nil {
		return err
	}

	var rolesBson bson.D
	err = bson.UnmarshalExtJSON([]byte(roles), true, &rolesBson)
	if err != nil {
		return err
	}

	var privilegesBson bson.D
	err = bson.UnmarshalExtJSON([]byte(privileges), true, &privilegesBson)
	if err != nil {
		return err
	}

	command := bson.D{primitive.E{Key: roleCommand, Value: role}}

	command = append(command, rolesBson...)
	command = append(command, privilegesBson...)
	logger.Info(fmt.Sprintf("%s %s on host %s", roleCommand, role, conf.GetHost()))
	commandResult := client.Database(authDb).RunCommand(ctx, command)

	return commandResult.Err()
}

func (r *MongoServiceImpl) CreateOrUpdateRole(ctx context.Context, authDb, role string, roles, privileges string, addToShards bool) error {
	logger := AddLoggerContext(r.Logger, ctx)
	errMsg := "failed to create/update role %s on host %s, err: %v"

	err := r.runCreateOrUpdateRole(ctx, r.Configuration, authDb, role, roles, privileges)

	if err != nil {
		return fmt.Errorf(errMsg, role, r.Configuration.GetHost(), err)
	}

	if addToShards {
		rsHosts, err := r.GetReplicaSetHosts()
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get replicasets. This error can be ignored in case of single Mongos schema. Err: %v. ", err))
			return nil
		}

		for _, host := range rsHosts {
			conf := &MongoConfigurationImpl{
				Hostname:   host,
				AuthDb:     r.Configuration.GetAuthDb(),
				User:       r.Configuration.GetUser(),
				Pass:       r.Configuration.GetPassword(),
				TLSEnabled: r.Configuration.IsTLSEnabled(),
				CAPath:     r.Configuration.GetCAPath(),
			}

			err = r.runCreateOrUpdateRole(ctx, conf, authDb, role, roles, privileges)
			if err != nil {
				return fmt.Errorf(errMsg, role, host, err)
			}
		}
	}

	return nil
}

func (r *MongoServiceImpl) runCreateOrUpdateUser(ctx context.Context, conf MongoConfiguration,
	username, pass, database, authDb string, rolesBson interface{}, force bool) error {

	logger := AddLoggerContext(r.Logger, ctx)
	exists, err := r.IsUserExist(ctx, conf, username, authDb)
	if err != nil {
		return err
	}

	var callFunc func(client *mongo.Client) (interface{}, error)
	if !exists || force {
		callFunc = r.createUser(ctx, username, pass, database, authDb, rolesBson)

	} else {
		callFunc = r.updateUser(ctx, username, pass, database, authDb, rolesBson)
	}

	logger.Debug(fmt.Sprintf("create/update user %v started", username))
	client, err := GetMongoClient(conf)
	if err != nil {
		return err
	}

	_, err = callFunc(client)
	return err

}

func (r *MongoServiceImpl) CreateOrUpdateUser(ctx context.Context, username, pass, database, authDb, roles string, addToShards, force bool) error {
	logger := AddLoggerContext(r.Logger, ctx)
	logger.Debug(fmt.Sprintf("check user %v exists on host %s", username, r.Configuration.GetHost()))

	errMsg := "failed to create/update user %s on host %s, err: %v"

	var rolesBson interface{}

	if roles != "" {
		err := bson.UnmarshalExtJSON([]byte(roles), true, &rolesBson)
		if err != nil {
			return err
		}
	}

	err := r.runCreateOrUpdateUser(ctx, r.Configuration, username, pass, database, authDb, rolesBson, force)
	if err != nil {
		return fmt.Errorf(errMsg, username, r.Configuration.GetHost(), err)
	}

	if addToShards {
		rsHosts, err := r.GetReplicaSetHosts()

		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get replicasets. This error can be ignored in case of single Mongos schema. Err: %v. ", err))
			return nil
		}

		for _, host := range rsHosts {
			conf := &MongoConfigurationImpl{
				Hostname:   host,
				AuthDb:     r.Configuration.GetAuthDb(),
				User:       r.Configuration.GetUser(),
				Pass:       r.Configuration.GetPassword(),
				TLSEnabled: r.Configuration.IsTLSEnabled(),
				CAPath:     r.Configuration.GetCAPath(),
			}

			err := r.runCreateOrUpdateUser(ctx, conf, username, pass, database, authDb, rolesBson, force)
			if err != nil {
				return fmt.Errorf(errMsg, username, host, err)
			}
		}
	}

	logger.Debug(fmt.Sprintf("create/update user %v finished", username))

	return err
}

func (r *MongoServiceImpl) createUser(ctx context.Context, username string, pass string, database string, authDb string, roles interface{}) func(client *mongo.Client) (interface{}, error) {
	logger := AddLoggerContext(r.Logger, ctx)
	// var bRoles []bson.M
	// if roles == nil {
	// 	roles = []bson.M{{"role": dbOwner, "db": database}}
	// }
	// } else if role == "streaming" {
	// 	roles = []bson.M{{"role": read, "db": database}, {"role": "streaming", "db": "admin"}}
	// } else {
	// 	roles = []bson.M{{"role": role, "db": database}}
	// }

	if authDb != "" {
		database = authDb
	}

	return func(client *mongo.Client) (interface{}, error) {
		command := bson.D{primitive.E{Key: "createUser", Value: username},
			primitive.E{Key: "pwd", Value: pass},
		}

		if roles != nil {
			command = append(command, roles.(bson.D)...)
		} else {
			command = append(command, bson.E{Key: "roles", Value: []bson.M{{"role": dbOwner, "db": database}}})
		}
		logger.Info(fmt.Sprintf("Creating user %s with role %v", username, roles))
		commandResult := client.Database(database).RunCommand(ctx, command)
		return nil, commandResult.Err()
	}
}

func (r *MongoServiceImpl) updateUser(ctx context.Context, username string, pass string, database string, authDb string, roles interface{}) func(client *mongo.Client) (interface{}, error) {
	logger := AddLoggerContext(r.Logger, ctx)
	// var bRoles []bson.M
	// if role == "" || role == dbOwner {
	// 	roles = []bson.M{{"role": dbOwner, "db": database}}
	// } else if role == "streaming" {
	// 	roles = []bson.M{{"role": read, "db": database}, {"role": "streaming", "db": "admin"}}
	// } else {
	// 	roles = []bson.M{{"role": role, "db": database}}
	// }

	update := bson.D{{"updateUser", username}}
	update = append(update, roles.(bson.D)...)

	if pass != "" {
		update = append(update, bson.E{"pwd", pass})
	}

	if authDb != "" {
		database = authDb
	}
	return func(client *mongo.Client) (interface{}, error) {
		logger.Info(fmt.Sprintf("Updating user %s role", username))
		commandResult := client.Database(database).RunCommand(ctx, update)

		return commandResult, commandResult.Err()
	}
}

func (r *MongoServiceImpl) IsUserExist(ctx context.Context, conf MongoConfiguration, username string, dbName string) (bool, error) {
	client, err := GetMongoClient(conf)
	if err != nil {
		return false, nil
	}
	userInfo := client.Database(dbName).RunCommand(ctx,
		bson.D{primitive.E{Key: "usersInfo", Value: username}})

	if userInfo.Err() != nil {
		return false, userInfo.Err()
	}

	var user bson.M
	userInfo.Decode(&user)

	users := []interface{}(user["users"].(primitive.A))
	return len(users) > 0, nil
}

func (r *MongoServiceImpl) IsRoleExist(ctx context.Context, conf MongoConfiguration, roleName, dbName string) (bool, error) {
	client, err := GetMongoClient(conf)
	if err != nil {
		return false, nil
	}
	rolesInfo := client.Database(dbName).RunCommand(ctx,
		bson.D{primitive.E{Key: "rolesInfo", Value: roleName}})

	if rolesInfo.Err() != nil {
		return false, rolesInfo.Err()
	}

	var role bson.M
	rolesInfo.Decode(&role)

	roles := []interface{}(role["roles"].(primitive.A))
	return len(roles) > 0, nil
}

func (r *MongoServiceImpl) GetReplicaSetHosts() ([]string, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	listShards := client.Database("admin").RunCommand(context.TODO(),
		bson.D{primitive.E{Key: "listShards", Value: 1}})

	if listShards.Err() != nil {
		return nil, listShards.Err()
	}

	var shardsResponse bson.M
	listShards.Decode(&shardsResponse)

	shards := []interface{}(shardsResponse["shards"].(primitive.A))

	if len(shards) == 0 {
		return nil, fmt.Errorf("Shard list is empty")
	}

	var hosts []string = make([]string, len(shards))
	for i, shard := range shards {
		s := shard.(primitive.M)
		hosts[i] = strings.Split(s["host"].(string), "/")[1]
	}

	return hosts, nil
}

func (r *MongoServiceImpl) UpdateUserPassword(ctx context.Context, username string, password string, dbName string) error {
	client, err := GetMongoClient(r.Configuration)
	logger := AddLoggerContext(r.Logger, ctx)
	if err != nil {
		return err
	}
	logger.Info(fmt.Sprintf("Updating user %s password", username))
	commandResult := client.Database(dbName).RunCommand(ctx, bson.D{{"updateUser", username}, {"pwd", password}})

	return commandResult.Err()

}

func (r *MongoServiceImpl) DropUser(ctx context.Context, username string) error {
	logger := AddLoggerContext(r.Logger, ctx)
	entities := strings.Split(username, ":")
	if len(entities) != 2 {
		return errors.New("The format of the incoming data is incorrect. Name must be \"dbName:username\"")
	}
	dbName := entities[0]
	username = entities[1]

	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return err
	}
	logger.Info(fmt.Sprintf("Dropping user %s", username))
	commandResult := client.Database(dbName).
		RunCommand(ctx, bson.D{primitive.E{Key: "dropUser", Value: username}})
	return commandResult.Err()
}

func (r *MongoServiceImpl) DropDatabase(ctx context.Context, dbName string) error {
	logger := AddLoggerContext(r.Logger, ctx)
	logger.Info(fmt.Sprintf("Dropping database %s", dbName))
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return err
	}
	return client.Database(dbName).Drop(context.TODO())

}

func (r *MongoServiceImpl) ListDatabases(ctx context.Context) ([]string, error) {
	logger := AddLoggerContext(r.Logger, ctx)
	logger.Info("ListDatabases databases")
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	return client.ListDatabaseNames(context.TODO(), bson.D{{}})

}

func (r *MongoServiceImpl) GetOne(ctx context.Context, dbName string, collection string) (*mongo.SingleResult, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	return client.Database(dbName).Collection(collection).FindOne(ctx, bson.M{}), nil
}

func (r *MongoServiceImpl) InsertOrUpdate(ctx context.Context, dbName string, collection string, data bson.D) (*mongo.UpdateResult, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	opts := options.Update().SetUpsert(true)
	return client.Database(dbName).Collection(collection).UpdateMany(ctx, bson.M{}, bson.D{{"$set", data}}, opts)

}

func (r *MongoServiceImpl) InsertOne(ctx context.Context, dbName string, collection string, data bson.D) (*mongo.InsertOneResult, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	coll := client.Database(dbName).Collection(collection)
	return coll.InsertOne(ctx, data)

}

func (r *MongoServiceImpl) GetRoles(ctx context.Context, dbName string) ([]string, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return nil, err
	}
	commandResult := client.Database(dbName).RunCommand(ctx, bson.D{{"usersInfo", 1}})

	var bRoles bson.M
	var roles []string
	err = commandResult.Decode(&bRoles)
	if err != nil {
		return nil, err
	}

	rolesMap := map[string]interface{}(bRoles)
	if paRolesMap, ok := rolesMap["users"].(primitive.A); ok {
		for _, dataMap := range []interface{}(paRolesMap) {
			dataMap2 := map[string]interface{}(dataMap.(primitive.M))
			roles = append(roles, dataMap2["user"].(string))
		}
	}
	return roles, commandResult.Err()

}

func (r *MongoServiceImpl) GetDbOwner(ctx context.Context, dbName string) (string, error) {
	client, err := GetMongoClient(r.Configuration)
	if err != nil {
		return "", err
	}
	tries := 3
	for i := 0; i < tries; i++ {
		user, err := findDbOwner(ctx, client, dbName, dbName)
		if err != nil {
			user, err = findDbOwner(ctx, client, dbName, "admin")
			if err == nil {
				return user, nil
			}
		} else {
			return user, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", errors.New("can't find user")

}

func findDbOwner(ctx context.Context, client *mongo.Client, dbName, authDb string) (string, error) {
	findCommand := bson.D{{"usersInfo", 1}, {"filter", bson.M{"roles": bson.M{"role": "dbOwner", "db": dbName}}}}
	commandResult := client.Database(authDb).RunCommand(context.TODO(), findCommand)
	var usersResponse bson.M
	if commandResult.Err() == nil {
		commandResult.Decode(&usersResponse)
		responseMap := map[string]interface{}(usersResponse)
		users := responseMap["users"].(bson.A)
		if len(users) != 0 {
			user := users[0].(bson.M)
			username := user["user"].(string)
			return username, nil
		} else {
			return "", mongo.ErrNoDocuments
		}
	}
	return "", commandResult.Err()
}

type MongoConfiguration interface {
	GetHost() string
	GetPort() int
	GetUser() string
	GetPassword() string
	GetAuthDb() string
	IsTLSEnabled() bool
	GetCAPath() string
}

type MongoConfigurationImpl struct {
	Hostname   string
	Port       int
	User       string
	Pass       string
	AuthDb     string
	TLSEnabled bool
	CAPath     string
	client     *mongo.Client
}

var _ MongoConfiguration = &MongoConfigurationImpl{}

func (r *MongoConfigurationImpl) GetUser() string {
	return r.User
}

func (r *MongoConfigurationImpl) GetHost() string {
	return r.Hostname
}

func (r *MongoConfigurationImpl) GetPort() int {
	return r.Port
}

func (r *MongoConfigurationImpl) GetPassword() string {
	return r.Pass
}

func (r *MongoConfigurationImpl) GetAuthDb() string {
	return r.AuthDb
}

func (r *MongoConfigurationImpl) GetCAPath() string {
	return r.CAPath
}

func (r *MongoConfigurationImpl) IsTLSEnabled() bool {
	// if value, exists := os.LookupEnv("TLS_ENABLED"); exists {
	// 	return value == "true"
	// }
	// return false
	return r.TLSEnabled
}

func AddLoggerContext(logger *zap.Logger, ctx context.Context) *zap.Logger {
	return logger.With(zap.ByteString("request_id", []byte(func() string {
		if v := ctx.Value("request_id"); v != nil {
			return fmt.Sprintf("%s", v)
		}
		return ""
	}())))
}
