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

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	redisTestKeyPrefix    = "thunder"
	redisTestDeploymentID = "deployment-1"
)

func newRedisStoreUnderTest(client redisClient) *redisStore {
	return &redisStore{
		client:       client,
		keyPrefix:    redisTestKeyPrefix,
		deploymentID: redisTestDeploymentID,
	}
}

func TestRedisStore_jtiKey(t *testing.T) {
	store := newRedisStoreUnderTest(newRedisClientMock(t))
	got := store.jtiKey("dpop", "xyz")
	assert.Equal(t, "thunder:runtime:deployment-1:jti:dpop:xyz", got)
}

func TestRedisStore_RecordJTI_Inserted(t *testing.T) {
	mockClient := newRedisClientMock(t)
	store := newRedisStoreUnderTest(mockClient)
	expiry := time.Now().Add(30 * time.Second)
	expectedKey := "thunder:runtime:deployment-1:jti:dpop:jti-1"

	cmd := redis.NewBoolCmd(context.Background())
	cmd.SetVal(true)
	mockClient.On("SetNX",
		mock.Anything,
		expectedKey,
		mock.Anything,
		mock.MatchedBy(func(d time.Duration) bool { return d > 0 && d <= 31*time.Second }),
	).Return(cmd)

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", expiry)
	require.NoError(t, err)
	assert.True(t, inserted)
}

func TestRedisStore_RecordJTI_Replay(t *testing.T) {
	mockClient := newRedisClientMock(t)
	store := newRedisStoreUnderTest(mockClient)

	cmd := redis.NewBoolCmd(context.Background())
	cmd.SetVal(false)
	mockClient.On("SetNX", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(cmd)

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, inserted)
}

func TestRedisStore_RecordJTI_BackendError(t *testing.T) {
	mockClient := newRedisClientMock(t)
	store := newRedisStoreUnderTest(mockClient)

	cmd := redis.NewBoolCmd(context.Background())
	cmd.SetErr(errors.New("connection refused"))
	mockClient.On("SetNX", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(cmd)

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", time.Now().Add(time.Minute))
	require.Error(t, err)
	assert.False(t, inserted)
	assert.Contains(t, err.Error(), "failed to record jti in Redis")
}

func TestRedisStore_RecordJTI_ExpiryInPastIsNotInserted(t *testing.T) {
	// Callers already reject expired proofs before reaching the store, so SetNX must
	// never be invoked when TTL would be non-positive.
	mockClient := newRedisClientMock(t)
	store := newRedisStoreUnderTest(mockClient)

	inserted, err := store.RecordJTI(context.Background(), "dpop", "jti-1", time.Now().Add(-time.Minute))
	require.NoError(t, err)
	assert.True(t, inserted)
}

// TestRedisStore_RecordJTI_NamespaceIsolation guards against accidental key-format
// changes that would collapse two namespaces with the same jti into the same Redis key.
func TestRedisStore_RecordJTI_NamespaceIsolation(t *testing.T) {
	mockClient := newRedisClientMock(t)
	store := newRedisStoreUnderTest(mockClient)
	expiry := time.Now().Add(30 * time.Second)

	cmd1 := redis.NewBoolCmd(context.Background())
	cmd1.SetVal(true)
	cmd2 := redis.NewBoolCmd(context.Background())
	cmd2.SetVal(true)

	mockClient.On("SetNX", mock.Anything,
		"thunder:runtime:deployment-1:jti:dpop:j",
		mock.Anything, mock.Anything).Return(cmd1).Once()
	mockClient.On("SetNX", mock.Anything,
		"thunder:runtime:deployment-1:jti:client_assertion:j",
		mock.Anything, mock.Anything).Return(cmd2).Once()

	ok1, err := store.RecordJTI(context.Background(), "dpop", "j", expiry)
	require.NoError(t, err)
	assert.True(t, ok1)
	ok2, err := store.RecordJTI(context.Background(), "client_assertion", "j", expiry)
	require.NoError(t, err)
	assert.True(t, ok2)
}
