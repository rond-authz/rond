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

var rangeOperatorStrategies = map[string]func(pipeline *[]bson.M, fieldName string, fieldValue interface{}){
	"lt":  HandleLessThan,
	"gt":  HandleGreaterThan,
	"lte": HandleLessThanEquals,
	"gte": HandleGreaterThanEquals,
}

func HandleRangeOperation(operation string, pipeline *[]bson.M, fieldName string, fieldValue interface{}) {
	if strategy, ok := rangeOperatorStrategies[operation]; ok {
		strategy(pipeline, fieldName, fieldValue)
	}
}
