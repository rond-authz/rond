package opatranslator

import (
	"go.mongodb.org/mongo-driver/bson"
)

type Queries struct {
	Pipeline bson.M
}

// Parse the == into equivalent mongo query.
func HandleEquals(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$eq": fieldValue}}
	*pipeline = append(*pipeline, filter)
}

// Parse the != into equivalent mongo query.
func HandleNotEquals(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$ne": fieldValue}}
	*pipeline = append(*pipeline, filter)
}

// Parse the < into equivalent mongo query.
func HandleLessThan(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$lt": fieldValue}}
	*pipeline = append(*pipeline, filter)
}

// Parse the > into equivalent mongo query.
func HandleGreaterThan(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$gt": fieldValue}}
	*pipeline = append(*pipeline, filter)
}

// Parse the <= into equivalent mongo query.
func HandleLessThanEquals(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$lte": fieldValue}}
	*pipeline = append(*pipeline, filter)
}

// Parse the >= into equivalent mongo query.
func HandleGreaterThanEquals(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$gte": fieldValue}}
	*pipeline = append(*pipeline, filter)
}
