// Copyright 2021 Mia srl
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

package opatranslator

import (
	"reflect"

	"go.mongodb.org/mongo-driver/bson"
)

type Queries struct {
	Pipeline bson.M
}

const (
	LtOp    = "lt"
	LteOp   = "lte"
	GtOp    = "gt"
	GteOp   = "gte"
	EqOp    = "eq"
	EqualOp = "equal"
	NeqOp   = "neq"
	// https://github.com/open-policy-agent/opa/blob/main/ast/builtins.go#L345
	InOp = "internal.member_2"
)

var rangeOperatorStrategies = map[string]func(pipeline *[]bson.M, fieldName string, fieldValue interface{}){
	LtOp:    HandleLessThan,
	GtOp:    HandleGreaterThan,
	LteOp:   HandleLessThanEquals,
	GteOp:   HandleGreaterThanEquals,
	EqOp:    HandleEquals,
	EqualOp: HandleEquals,
	NeqOp:   HandleNotEquals,
	InOp:    HandleIn,
}

func HandleOperations(operation string, pipeline *[]bson.M, fieldName string, fieldValue interface{}) bool {
	strategy, ok := rangeOperatorStrategies[operation]
	if ok {
		strategy(pipeline, fieldName, fieldValue)
	}
	return ok
}

// Parse the == into equivalent mongo query.
func HandleEquals(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	filter := bson.M{fieldName: bson.M{"$eq": fieldValue}}
	*pipeline = append(*pipeline, filter)
}

// Parse the in operator into equivalent mongo query.
func HandleIn(pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	reflectValue := reflect.ValueOf(fieldValue)

	mongoInOperatorValue := fieldValue
	if reflectValue.Kind() != reflect.Slice {
		mongoInOperatorValue = []interface{}{fieldValue}
	}

	filter := bson.M{fieldName: bson.M{"$in": mongoInOperatorValue}}
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
