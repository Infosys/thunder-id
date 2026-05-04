/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package security

import "strings"

const (
	// maxPublicPathLength defines the maximum allowed length for a public path.
	// This prevents potential DoS attacks via excessively long paths (even with safe regex).
	maxPublicPathLength = 4096
)

// UninitializedPermissionSentinel is returned by permission-resolution functions when
// InitSystemPermissions has not yet been called. It is intentionally unguessable so that
// any permission check performed before initialization fails closed.
const UninitializedPermissionSentinel = "__uninitialized__"

// publicPaths defines the list of public paths using glob patterns.
// - "*": Matches a single path segment (e.g., /a/*/b).
// - "**": Matches zero or more path segments (subpaths) at the end of the path (e.g., /a/**).
// Not allowed in the middle of the path (e.g., /a/**/b is invalid).
var publicPaths = []string{
	"/health/**",
	"/auth/**",
	"/register/passkey/**",
	"/flow/execute/**",
	"/flow/meta",
	"/oauth2/**",
	"/.well-known/openid-configuration/**",
	"/.well-known/oauth-authorization-server/**",
	"/.well-known/oauth-protected-resource",
	"/gate/**",
	"/console/**",
	"/error/**",
	"/design/resolve/**",
	"/i18n/languages",
	"/i18n/languages/*/translations/resolve",
	"/i18n/languages/*/translations/ns/*/keys/*/resolve",
	"/mcp/**", // MCP authorization is handled at MCP server handler.
}

// ---- Resource types ----

// ResourceType defines the category of system resource being acted upon.
type ResourceType string

// ResourceType defines the category of system resource being acted upon.
// ResourceTypeOU, ResourceTypeUser, ResourceTypeGroup, and ResourceTypeUserSchema are the supported values.
const (
	// ResourceTypeOU identifies an organization unit resource.
	ResourceTypeOU ResourceType = "ou"
	// ResourceTypeUser identifies a user resource.
	ResourceTypeUser ResourceType = "user"
	// ResourceTypeGroup identifies a group resource.
	ResourceTypeGroup ResourceType = "group"
	// ResourceTypeUserSchema identifies a user schema resource.
	ResourceTypeUserSchema ResourceType = "userschema"
)

// ---- Actions ----

// Action defines a system operation that can be authorized.
type Action string

const (
	// ActionCreateOU creates a new organization unit.
	ActionCreateOU Action = "ou:create"
	// ActionReadOU reads an organization unit.
	ActionReadOU Action = "ou:read"
	// ActionUpdateOU updates an organization unit.
	ActionUpdateOU Action = "ou:update"
	// ActionDeleteOU deletes an organization unit.
	ActionDeleteOU Action = "ou:delete"
	// ActionListOUs lists organization units.
	ActionListOUs Action = "ou:list"
	// ActionListChildOUs lists child organization units of a parent OU.
	ActionListChildOUs Action = "ou:list-children"

	// ActionCreateUser creates a new user.
	ActionCreateUser Action = "user:create"
	// ActionReadUser reads a user.
	ActionReadUser Action = "user:read"
	// ActionUpdateUser updates a user.
	ActionUpdateUser Action = "user:update"
	// ActionDeleteUser deletes a user.
	ActionDeleteUser Action = "user:delete"
	// ActionListUsers lists users.
	ActionListUsers Action = "user:list"

	// ActionCreateGroup creates a new group.
	ActionCreateGroup Action = "group:create"
	// ActionReadGroup reads a group.
	ActionReadGroup Action = "group:read"
	// ActionUpdateGroup updates a group.
	ActionUpdateGroup Action = "group:update"
	// ActionDeleteGroup deletes a group.
	ActionDeleteGroup Action = "group:delete"
	// ActionListGroups lists groups.
	ActionListGroups Action = "group:list"

	// ActionCreateUserSchema creates a new user schema.
	ActionCreateUserSchema Action = "userschema:create"
	// ActionReadUserSchema reads a user schema.
	ActionReadUserSchema Action = "userschema:read"
	// ActionUpdateUserSchema updates a user schema.
	ActionUpdateUserSchema Action = "userschema:update"
	// ActionDeleteUserSchema deletes a user schema.
	ActionDeleteUserSchema Action = "userschema:delete"
	// ActionListUserSchemas lists user schemas.
	ActionListUserSchemas Action = "userschema:list"
)

// ---- Permissions ----

// SystemPermissions holds the runtime-resolved permission strings for the system resource server.
// All values are set by InitSystemPermissions and must not be used before it is called.
type SystemPermissions struct {
	Root           string
	OU             string
	OUView         string
	User           string
	UserView       string
	Group          string
	GroupView      string
	UserSchema     string
	UserSchemaView string
}

// sysPerms holds the active system permissions, initialized by InitSystemPermissions.
var sysPerms *SystemPermissions

// buildPermission constructs a permission string by joining non-empty parts with ":".
func buildPermission(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, ":")
}

// InitSystemPermissions initializes the system permission strings using the given handle prefix.
// When handle is empty, permissions match the legacy values ("system", "system:ou", etc.).
// When handle is non-empty (e.g. "mgmt"), permissions are prefixed ("mgmt:system", "mgmt:system:ou", etc.).
// This function must be called once at startup before any service or middleware uses permissions.
func InitSystemPermissions(handle string) {
	p := &SystemPermissions{
		Root:           buildPermission(handle, "system"),
		OU:             buildPermission(handle, "system", "ou"),
		OUView:         buildPermission(handle, "system", "ou", "view"),
		User:           buildPermission(handle, "system", "user"),
		UserView:       buildPermission(handle, "system", "user", "view"),
		Group:          buildPermission(handle, "system", "group"),
		GroupView:      buildPermission(handle, "system", "group", "view"),
		UserSchema:     buildPermission(handle, "system", "userschema"),
		UserSchemaView: buildPermission(handle, "system", "userschema", "view"),
	}
	sysPerms = p

	actionPermissionMap = map[Action]string{
		// Organization unit actions.
		ActionCreateOU:     p.OU,
		ActionReadOU:       p.OUView,
		ActionUpdateOU:     p.OU,
		ActionDeleteOU:     p.OU,
		ActionListOUs:      p.OUView,
		ActionListChildOUs: p.OU,

		// User actions.
		ActionCreateUser: p.User,
		ActionReadUser:   p.UserView,
		ActionUpdateUser: p.User,
		ActionDeleteUser: p.User,
		ActionListUsers:  p.UserView,

		// Group actions.
		ActionCreateGroup: p.Group,
		ActionReadGroup:   p.GroupView,
		ActionUpdateGroup: p.Group,
		ActionDeleteGroup: p.Group,
		ActionListGroups:  p.GroupView,

		// User schema actions.
		ActionCreateUserSchema: p.UserSchema,
		ActionReadUserSchema:   p.UserSchemaView,
		ActionUpdateUserSchema: p.UserSchema,
		ActionDeleteUserSchema: p.UserSchema,
		ActionListUserSchemas:  p.UserSchemaView,
	}

	apiPermissionEntries = []apiPermissionEntry{
		// Self-service paths — accessible to any authenticated user (empty permission).
		// Listed before their parent wildcards so they always win on first-match.
		{"GET /users/me", ""},
		{"PUT /users/me", ""},
		{"GET /users/me/**", ""},
		{"PUT /users/me/**", ""},
		{"POST /users/me/update-credentials", ""},
		{"GET /register/passkey/**", ""},
		{"POST /register/passkey/**", ""},

		// Organization unit APIs — exact named paths before wildcards.
		{"GET /organization-units/tree", p.OUView},
		{"PUT /organization-units/tree", p.OU},
		{"DELETE /organization-units/tree", p.OU},
		{"GET /organization-units", p.OUView},
		{"POST /organization-units", p.OU},
		{"GET /organization-units/**", p.OUView},
		{"PUT /organization-units/**", p.OU},
		{"DELETE /organization-units/**", p.OU},

		// User APIs.
		{"GET /users", p.UserView},
		{"POST /users", p.User},
		{"GET /users/**", p.UserView},
		{"PUT /users/**", p.User},
		{"DELETE /users/**", p.User},

		// Group APIs.
		{"GET /groups", p.GroupView},
		{"POST /groups", p.Group},
		{"GET /groups/**", p.GroupView},
		{"POST /groups/**", p.Group},
		{"PUT /groups/**", p.Group},
		{"DELETE /groups/**", p.Group},

		// User schema APIs.
		{"GET /user-schemas", p.UserSchemaView},
		{"POST /user-schemas", p.UserSchema},
		{"GET /user-schemas/**", p.UserSchemaView},
		{"PUT /user-schemas/**", p.UserSchema},
		{"DELETE /user-schemas/**", p.UserSchema},

		// Import APIs.
		{"POST /import", p.Root},
		{"POST /import/delete", p.Root},
	}
}

// GetSystemPermissions returns the active system permissions.
// Returns nil if InitSystemPermissions has not been called.
func GetSystemPermissions() *SystemPermissions {
	return sysPerms
}

// ---- Action → Permission map ----

// actionPermissionMap maps each system action to the minimum permission required to perform it.
// Actions not present in this map default to requiring the root system permission.
// Rebuilt by InitSystemPermissions at startup.
var actionPermissionMap map[Action]string

// ---- API → Permission map ----

// apiPermissionEntry pairs a "METHOD glob-path" pattern with the minimum permission
// required for matching requests.
type apiPermissionEntry struct {
	pattern    string
	permission string
}

// apiPermissionEntries defines the ordered set of API permission rules.
// Evaluation is first-match-wins, so more specific patterns must appear before
// broader wildcard patterns. Pattern syntax (applied to the full "METHOD /path" string)
// follows the same glob rules used by publicPaths:
//   - "*"  matches exactly one path segment (e.g., a resource ID).
//   - "**" matches zero or more path segments; only valid as the final component
//     after "/" (e.g., "GET /users/me/**" covers all sub-paths of /users/me).
//
// Rebuilt by InitSystemPermissions at startup.
var apiPermissionEntries []apiPermissionEntry

// ---- Helper functions ----

// HasSystemPermission returns true if the caller holds the root system permission.
// This is a fast-path check used to grant unconditional access (skipping policy evaluation).
func HasSystemPermission(permissions []string) bool {
	if sysPerms == nil {
		return false
	}
	for _, p := range permissions {
		if p == sysPerms.Root {
			return true
		}
	}
	return false
}

// HasSufficientPermission returns true if any permission in userPermissions satisfies
// the required permission using hierarchical scope matching.
//
// Matching rules:
//   - Empty required: always satisfied (self-service paths with no specific permission requirement)
//   - Exact match: "system:ou:view" satisfies "system:ou:view"
//   - Parent scope: "system:ou" satisfies "system:ou:view" (parent covers all children)
//   - Root scope: "system" satisfies any "system:*" permission
func HasSufficientPermission(userPermissions []string, required string) bool {
	if required == "" {
		return true
	}
	for _, p := range userPermissions {
		if p == required || strings.HasPrefix(required, p+":") {
			return true
		}
	}
	return false
}

// ResolveActionPermission returns the minimum permission required to perform the given
// action. Falls back to the root system permission for actions not listed in the action permission map.
func ResolveActionPermission(action Action) string {
	if perm, ok := actionPermissionMap[action]; ok {
		return perm
	}
	if sysPerms != nil {
		return sysPerms.Root
	}
	return UninitializedPermissionSentinel
}
