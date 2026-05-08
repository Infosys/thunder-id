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

import dbmodel "github.com/thunder-id/thunder-id/internal/system/database/model"

// queryInsertJTI atomically inserts a (deployment_id, namespace, jti) replay-cache
// entry. On primary-key conflict, the row is silently skipped so RowsAffected==0
// signals a replay.
var queryInsertJTI = dbmodel.DBQuery{
	ID: "JTQ-01",
	Query: `INSERT INTO "JTI_REPLAY" (DEPLOYMENT_ID, NAMESPACE, JTI, EXPIRY_TIME) ` +
		`VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
	PostgresQuery: `INSERT INTO "JTI_REPLAY" (DEPLOYMENT_ID, NAMESPACE, JTI, EXPIRY_TIME) ` +
		`VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
	SQLiteQuery: `INSERT OR IGNORE INTO "JTI_REPLAY" (DEPLOYMENT_ID, NAMESPACE, JTI, EXPIRY_TIME) ` +
		`VALUES ($1, $2, $3, $4)`,
}
