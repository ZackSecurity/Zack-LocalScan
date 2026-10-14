// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZackSecurity

package mongodb

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"time"
)

// Timeout is the connection timeout for MongoDB. Hardcoded 4s — TCP+SCRAM handshake+ping.
var Timeout = 4 * time.Second

func Check(Host, Username, Password string, Port int) error {
	dataSourceName := fmt.Sprintf("mongodb://%v:%v@%v:%v/?authMechanism=SCRAM-SHA-1", Username, Password, Host, Port)
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	// establish the MongoDB connection
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dataSourceName))
	if err != nil {
		return err
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return err
	}
	return nil
}
