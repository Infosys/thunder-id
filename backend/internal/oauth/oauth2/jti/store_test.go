/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package jti

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunder-id/tests/mocks/database/providermock"
)

const testDeploymentID = "deployment-1"

func newDBStoreUnderTest() (*dbStore, *providermock.DBProviderInterfaceMock, *providermock.DBClientInterfaceMock) {
	dbProvider := &providermock.DBProviderInterfaceMock{}
	dbClient := &providermock.DBClientInterfaceMock{}
	store := &dbStore{dbProvider: dbProvider, deploymentID: testDeploymentID}
	return store, dbProvider, dbClient
}

func TestDBStore_RecordJTI_Inserted(t *testing.T) {
	store, dbProvider, dbClient := newDBStoreUnderTest()
	expiry := time.Now().Add(time.Minute).UTC()
	dbProvider.On("GetRuntimeDBClient").Return(dbClient, nil)
	dbClient.On("ExecuteContext", mock.Anything, queryInsertJTI,
		testDeploymentID, "dpop", "jti-1",
		mock.MatchedBy(func(t time.Time) bool { return !t.IsZero() }),
	).Return(int64(1), nil)

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", expiry)
	require.NoError(t, err)
	assert.True(t, inserted)
	dbProvider.AssertExpectations(t)
	dbClient.AssertExpectations(t)
}

func TestDBStore_RecordJTI_Replay(t *testing.T) {
	store, dbProvider, dbClient := newDBStoreUnderTest()
	dbProvider.On("GetRuntimeDBClient").Return(dbClient, nil)
	dbClient.On("ExecuteContext", mock.Anything, queryInsertJTI,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(int64(0), nil)

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, inserted, "RowsAffected==0 must be reported as a replay")
}

func TestDBStore_RecordJTI_DBClientError(t *testing.T) {
	store, dbProvider, _ := newDBStoreUnderTest()
	dbProvider.On("GetRuntimeDBClient").Return(nil, errors.New("conn failed"))

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", time.Now().Add(time.Minute))
	require.Error(t, err)
	assert.False(t, inserted)
	assert.Contains(t, err.Error(), "failed to get database client")
}

func TestDBStore_RecordJTI_ExecuteError(t *testing.T) {
	store, dbProvider, dbClient := newDBStoreUnderTest()
	dbProvider.On("GetRuntimeDBClient").Return(dbClient, nil)
	dbClient.On("ExecuteContext", mock.Anything, queryInsertJTI,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(int64(0), errors.New("insert failed"))

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", time.Now().Add(time.Minute))
	require.Error(t, err)
	assert.False(t, inserted)
	assert.Contains(t, err.Error(), "failed to insert jti")
}

func TestDBStore_RecordJTI_PassesUTCExpiry(t *testing.T) {
	// Local-time inputs must be persisted in UTC for cross-timezone consistency.
	store, dbProvider, dbClient := newDBStoreUnderTest()
	loc, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)
	local := time.Now().In(loc)

	dbProvider.On("GetRuntimeDBClient").Return(dbClient, nil)
	dbClient.On("ExecuteContext", mock.Anything, queryInsertJTI,
		testDeploymentID, "dpop", "jti-utc",
		mock.MatchedBy(func(t time.Time) bool { return t.Location() == time.UTC }),
	).Return(int64(1), nil)

	_, err = store.RecordJTI(context.Background(), "dpop", "jti-utc", local)
	require.NoError(t, err)
}

// TestDBStore_RecordJTI_NamespaceIsolation locks in the contract that two distinct
// namespaces can carry the same jti without colliding — i.e. namespace participates
// in the primary key.
func TestDBStore_RecordJTI_NamespaceIsolation(t *testing.T) {
	store, dbProvider, dbClient := newDBStoreUnderTest()
	dbProvider.On("GetRuntimeDBClient").Return(dbClient, nil)
	dbClient.On("ExecuteContext", mock.Anything, queryInsertJTI,
		testDeploymentID, "dpop", "j", mock.Anything,
	).Return(int64(1), nil).Once()
	dbClient.On("ExecuteContext", mock.Anything, queryInsertJTI,
		testDeploymentID, "client_assertion", "j", mock.Anything,
	).Return(int64(1), nil).Once()

	ok1, err := store.RecordJTI(context.Background(), "dpop", "j", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, ok1)
	ok2, err := store.RecordJTI(context.Background(), "client_assertion", "j", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, ok2)
	dbClient.AssertExpectations(t)
}
