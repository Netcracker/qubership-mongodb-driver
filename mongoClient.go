package driver

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"sync"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoClients struct {
	configuration MongoConfiguration
	client        *mongo.Client
}

var mu sync.Mutex
var clients []MongoClients

func GetMongoClient(conf MongoConfiguration) (*mongo.Client, error) {
	mu.Lock()
	defer func() {
		mu.Unlock()
	}()

	for _, client := range clients {
		if reflect.DeepEqual(client.configuration, conf) {
			return client.client, nil
		}
	}
	client, err := createMongoClient(conf)
	if err != nil {
		return nil, err
	}

	clients = append(clients, MongoClients{configuration: conf, client: client})

	return client, err
}

func DisconnectMongoClient(conf MongoConfiguration) error {
	mu.Lock()
	defer mu.Unlock()
	index := -1
	for i, client := range clients {
		if reflect.DeepEqual(client.configuration, conf) {
			client.client.Disconnect(context.TODO())
			index = i
		}
	}

	if index != -1 {
		newClients := make([]MongoClients, 0)
		newClients = append(newClients, clients[:index]...)
		clients = append(newClients, clients[index+1:]...)
	}

	return nil
}

func createMongoClient(conf MongoConfiguration) (*mongo.Client, error) {
	var mainURI string
	var URIOptions string

	if conf.GetAuthDb() != "" {
		mainURI = fmt.Sprintf("mongodb://%s:%s@%s", url.QueryEscape(conf.GetUser()), url.QueryEscape(conf.GetPassword()), conf.GetHost())
		if conf.GetPort() != 0 {
			mainURI = mainURI + fmt.Sprintf(":%d", conf.GetPort())
		}
		URIOptions = fmt.Sprintf("/?authSource=%s", conf.GetAuthDb())
	} else {
		mainURI = fmt.Sprintf("mongodb://%s", conf.GetHost())
		if conf.GetPort() != 0 {
			mainURI = mainURI + fmt.Sprintf(":%d/", conf.GetPort())
		}
	}

	if conf.IsTLSEnabled() {

		tlsOptions := fmt.Sprintf("tls=true&tlsCAFile=%s", conf.GetCAPath())

		// remove before using production certs
		tlsOptions = fmt.Sprint(tlsOptions, "&tlsInsecure=true")

		if len(URIOptions) > 0 {
			URIOptions = fmt.Sprint(URIOptions, "&", tlsOptions)
		} else {
			URIOptions = fmt.Sprint("?", tlsOptions)
		}
	}

	return mongo.Connect(context.TODO(), options.Client().ApplyURI(mainURI+URIOptions))
}
