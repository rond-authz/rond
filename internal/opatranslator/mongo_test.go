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
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
)

func TestMongoTranslatorFunctions(t *testing.T) {
	t.Run("testing HandleEquals", func(t *testing.T) {
		query := []bson.M{}
		HandleEquals(&query, "test", 1)
		expected := []bson.M{{"test": bson.M{"$eq": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleEquals append to already existing", func(t *testing.T) {
		query := []bson.M{{"IWasAlreadyThere": 1}}
		HandleEquals(&query, "test", 1)
		expected := []bson.M{{"IWasAlreadyThere": 1}, {"test": bson.M{"$eq": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleNotEquals", func(t *testing.T) {
		query := []bson.M{}
		HandleNotEquals(&query, "test", 1)
		expected := []bson.M{{"test": bson.M{"$ne": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleNotEquals append to already existing", func(t *testing.T) {
		query := []bson.M{{"IWasAlreadyThere": 1}}
		HandleNotEquals(&query, "test", 1)
		expected := []bson.M{{"IWasAlreadyThere": 1}, {"test": bson.M{"$ne": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleLessThan", func(t *testing.T) {
		query := []bson.M{}
		HandleLessThan(&query, "test", 1)
		expected := []bson.M{{"test": bson.M{"$lt": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleLessThan append to already existing", func(t *testing.T) {
		query := []bson.M{{"IWasAlreadyThere": 1}}
		HandleLessThan(&query, "test", 1)
		expected := []bson.M{{"IWasAlreadyThere": 1}, {"test": bson.M{"$lt": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleGreaterThan", func(t *testing.T) {
		query := []bson.M{}
		HandleGreaterThan(&query, "test", 1)
		expected := []bson.M{{"test": bson.M{"$gt": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleGreaterThan append to already existing", func(t *testing.T) {
		query := []bson.M{{"IWasAlreadyThere": 1}}
		HandleGreaterThan(&query, "test", 1)
		expected := []bson.M{{"IWasAlreadyThere": 1}, {"test": bson.M{"$gt": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleLessThanEquals", func(t *testing.T) {
		query := []bson.M{}
		HandleLessThanEquals(&query, "test", 1)
		expected := []bson.M{{"test": bson.M{"$lte": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleLessThanEquals append to already existing", func(t *testing.T) {
		query := []bson.M{{"IWasAlreadyThere": 1}}
		HandleLessThanEquals(&query, "test", 1)
		expected := []bson.M{{"IWasAlreadyThere": 1}, {"test": bson.M{"$lte": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleGreaterThanEquals", func(t *testing.T) {
		query := []bson.M{}
		HandleGreaterThanEquals(&query, "test", 1)
		expected := []bson.M{{"test": bson.M{"$gte": 1}}}
		require.Equal(t, expected, query)
	})
	t.Run("testing HandleGreaterThanEquals append to already existing", func(t *testing.T) {
		query := []bson.M{{"IWasAlreadyThere": 1}}
		HandleGreaterThanEquals(&query, "test", 1)
		expected := []bson.M{{"IWasAlreadyThere": 1}, {"test": bson.M{"$gte": 1}}}
		require.Equal(t, expected, query)
	})
}
