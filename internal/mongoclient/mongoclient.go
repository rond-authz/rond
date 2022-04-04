package mongoclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/utils"
	"git.tools.mia-platform.eu/platform/core/rbac-service/types"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type MongoClient struct {
	client       *mongo.Client
	bindings     *mongo.Collection
	roles        *mongo.Collection
	databaseName string
}

const STATE string = "__STATE__"
const PUBLIC string = "PUBLIC"

// MongoClientInjectorMiddleware will inject into request context the
// mongo collections.
func MongoClientInjectorMiddleware(collections types.IMongoClient) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithMongoClient(r.Context(), collections)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func WithMongoClient(ctx context.Context, mongoClient types.IMongoClient) context.Context {
	return context.WithValue(ctx, types.MongoClientContextKey{}, mongoClient)
}

// GetMongoClientFromContext extracts mongo collections adapter struct from
// provided context.
func GetMongoClientFromContext(ctx context.Context) (types.IMongoClient, error) {
	collectionInterface := ctx.Value(types.MongoClientContextKey{})

	if collectionInterface == nil {
		return nil, nil
	}
	collections, ok := collectionInterface.(types.IMongoClient)
	if !ok {
		return nil, fmt.Errorf("no MongoDB collection found in context")
	}
	return collections, nil
}

func (mongoClient *MongoClient) Disconnect() {
	if mongoClient != nil {
		mongoClient.client.Disconnect(context.Background())
	}
}

func NewMongoClient(env config.EnvironmentVariables, logger *logrus.Logger) (*MongoClient, error) {
	if env.MongoDBUrl == "" {
		return nil, nil
	}
	if env.RolesCollectionName == "" || env.BindingsCollectionName == "" {
		return nil, fmt.Errorf(
			`MongoDB url is not empty, required variables might be missing: BindingsCollectionName: "%s",  RolesCollectionName: "%s"`,
			env.BindingsCollectionName,
			env.RolesCollectionName,
		)
	}

	parsedConnectionString, err := connstring.ParseAndValidate(env.MongoDBUrl)
	if err != nil {
		return nil, fmt.Errorf("failed MongoDB connection string validation: %s", err.Error())
	}

	clientOpts := options.Client().ApplyURI(env.MongoDBUrl)
	client, err := mongo.Connect(context.Background(), clientOpts)
	if err != nil {
		return nil, fmt.Errorf("error connecting to MongoDB: %s", err.Error())
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("error verifying MongoDB connection: %s", err.Error())
	}

	mongoClient := MongoClient{
		client:       client,
		databaseName: parsedConnectionString.Database,
		roles:        client.Database(parsedConnectionString.Database).Collection(env.RolesCollectionName),
		bindings:     client.Database(parsedConnectionString.Database).Collection(env.BindingsCollectionName),
	}
	return &mongoClient, nil
}

func (mongoClient *MongoClient) RetrieveUserBindings(ctx context.Context, user *types.User) ([]types.Binding, error) {
	filter := bson.M{
		"$and": []bson.M{
			{
				"$or": []bson.M{
					{"subjects": bson.M{"$elemMatch": bson.M{"$eq": user.UserID}}},
					{"groups": bson.M{"$elemMatch": bson.M{"$in": user.UserGroups}}},
				},
			},
			{STATE: PUBLIC},
		},
	}
	cursor, err := mongoClient.bindings.Find(
		ctx,
		filter,
	)
	if err != nil {
		return nil, err
	}
	bindingsResult := make([]types.Binding, 0)
	if err = cursor.All(ctx, &bindingsResult); err != nil {
		return nil, err
	}
	return bindingsResult, nil
}

func (mongoClient *MongoClient) RetrieveRoles(ctx context.Context) ([]types.Role, error) {
	filter := bson.M{
		STATE: PUBLIC,
	}
	cursor, err := mongoClient.roles.Find(
		ctx,
		filter,
	)
	if err != nil {
		return nil, err
	}
	rolesResult := make([]types.Role, 0)
	if err = cursor.All(ctx, &rolesResult); err != nil {
		return nil, err
	}
	return rolesResult, nil
}

func (mongoClient *MongoClient) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	filter := bson.M{
		"$and": []bson.M{
			{
				"roleId": bson.M{"$in": userRolesId},
			},
			{STATE: PUBLIC},
		},
	}
	cursor, err := mongoClient.roles.Find(
		ctx,
		filter,
	)
	if err != nil {
		return nil, err
	}
	rolesResult := make([]types.Role, 0)
	if err = cursor.All(ctx, &rolesResult); err != nil {
		return nil, err
	}
	return rolesResult, nil
}

func (mongoClient *MongoClient) FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error) {
	collection := mongoClient.client.Database(mongoClient.databaseName).Collection(collectionName)
	glogger.Get(ctx).WithFields(logrus.Fields{
		"mongoQuery":     query,
		"dbName":         mongoClient.databaseName,
		"collectionName": collectionName,
	}).Debug("performing query")

	result := collection.FindOne(ctx, query)

	var bsonDocument bson.D
	err := result.Decode(&bsonDocument)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			glogger.Get(ctx).WithField("error", logrus.Fields{"message": err.Error()}).Warn("no document found")
			return nil, nil
		}
		glogger.Get(ctx).WithField("error", logrus.Fields{"message": err.Error()}).Error("failed query decode")
		return nil, err
	}

	temporaryBytes, err := bson.MarshalExtJSON(bsonDocument, true, true)
	if err != nil {
		glogger.Get(ctx).WithField("error", logrus.Fields{"message": err.Error()}).Error("failed query result marshalling")
		return nil, err
	}

	var res map[string]interface{}
	if err := json.Unmarshal(temporaryBytes, &res); err != nil {
		glogger.Get(ctx).WithField("error", logrus.Fields{"message": err.Error()}).Error("failed query result deserialization")
		return nil, err
	}
	return res, nil
}

func (mongoClient *MongoClient) FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error) {
	collection := mongoClient.client.Database(mongoClient.databaseName).Collection(collectionName)
	glogger.Get(ctx).WithFields(logrus.Fields{
		"mongoQuery":     query,
		"dbName":         mongoClient.databaseName,
		"collectionName": collectionName,
	}).Debug("performing query")

	resultCursor, err := collection.Find(ctx, query)
	if err != nil {
		glogger.Get(ctx).WithField("error", logrus.Fields{"message": err.Error()}).Error("failed query execution")
		return nil, err
	}

	results := make([]interface{}, 0)
	if err := resultCursor.All(ctx, &results); err != nil {
		glogger.Get(ctx).WithField("error", logrus.Fields{"message": err.Error()}).Error("failed complete query result deserialization")
		return nil, err
	}

	for i := 0; i < len(results); i++ {
		temporaryBytes, err := bson.MarshalExtJSON(results[i], true, true)
		if err != nil {
			glogger.Get(ctx).WithFields(logrus.Fields{
				"error":       logrus.Fields{"message": err.Error()},
				"resultIndex": i,
			}).Error("failed query result marshalling")
			return nil, err
		}
		if err := json.Unmarshal(temporaryBytes, &results[i]); err != nil {
			glogger.Get(ctx).WithFields(logrus.Fields{
				"error":       logrus.Fields{"message": err.Error()},
				"resultIndex": i,
			}).Error("failed result document deserialization")
			return nil, err
		}
	}
	return results, nil
}

func RolesIDsFromBindings(bindings []types.Binding) []string {
	rolesIds := []string{}
	for _, binding := range bindings {
		for _, role := range binding.Roles {
			if !utils.Contains(rolesIds, role) {
				rolesIds = append(rolesIds, role)
			}
		}
	}
	return rolesIds
}

func RetrieveUserBindingsAndRoles(logger *logrus.Entry, req *http.Request, env config.EnvironmentVariables) (types.User, error) {
	requestContext := req.Context()
	mongoClient, err := GetMongoClientFromContext(requestContext)
	if err != nil {
		return types.User{}, fmt.Errorf("Unexpected error retrieving MongoDB Client from request context")
	}

	var user types.User

	user.UserGroups = strings.Split(req.Header.Get(env.UserGroupsHeader), ",")
	user.UserID = req.Header.Get(env.UserIdHeader)

	if mongoClient != nil && user.UserID != "" {
		user.UserBindings, err = mongoClient.RetrieveUserBindings(requestContext, &user)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user bindings")
			return types.User{}, fmt.Errorf("Error while retrieving user bindings: %s", err.Error())
		}

		userRolesIds := RolesIDsFromBindings(user.UserBindings)
		user.UserRoles, err = mongoClient.RetrieveUserRolesByRolesID(requestContext, userRolesIds)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user roles")

			return types.User{}, fmt.Errorf("Error while retrieving user Roles: %s", err.Error())
		}
	}
	return user, nil
}
