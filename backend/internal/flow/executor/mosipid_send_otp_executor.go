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

package executor

import (
	"fmt"

	"github.com/asgardeo/thunder/internal/authnprovider"
	"github.com/asgardeo/thunder/internal/flow/common"
	"github.com/asgardeo/thunder/internal/flow/core"

	"github.com/asgardeo/thunder/internal/system/log"
)

const (
	mosipIDSendOTPLoggerComponentName = "MosipIDSendOTPExecutor"
)

var IndividualIDInput = common.Input{
	Identifier: userAttributeUsername,
	Type:       common.InputTypeText,
	Required:   true,
}

// mosipIDSendOTPExecutor implements ExecutorInterface for sending OTP
// via the MOSIP ID external REST API.
type mosipIDSendOTPExecutor struct {
	core.ExecutorInterface
	mosipAuthnProvider *authnprovider.MOSIPAuthnProvider
	logger             *log.Logger
}

var _ core.ExecutorInterface = (*mosipIDSendOTPExecutor)(nil)

// newMosipIDSendOTPExecutor creates a new instance of mosipIDSendOTPExecutor.
func newMosipIDSendOTPExecutor(
	flowFactory core.FlowFactoryInterface,
	mosipAuthnProvider *authnprovider.MOSIPAuthnProvider,
) *mosipIDSendOTPExecutor {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, mosipIDSendOTPLoggerComponentName),
		log.String(log.LoggerKeyExecutorName, ExecutorNameMosipIDSendOTP))

	prerequisites := []common.Input{
		IndividualIDInput,
	}

	base := flowFactory.CreateExecutor(ExecutorNameMosipIDSendOTP, common.ExecutorTypeAuthentication,
		nil, prerequisites)

	return &mosipIDSendOTPExecutor{
		ExecutorInterface:  base,
		mosipAuthnProvider: mosipAuthnProvider,
		logger:             logger,
	}
}

// Execute executes the MOSIP ID send OTP executor logic.
func (e *mosipIDSendOTPExecutor) Execute(ctx *core.NodeContext) (*common.ExecutorResponse, error) {
	logger := e.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Executing MOSIP ID send OTP executor")

	execResp := &common.ExecutorResponse{
		ForwardedData: make(map[string]any),
	}

	if !e.ValidatePrerequisites(ctx, execResp) {
		logger.Debug("Prerequisites not met for MOSIP ID send OTP executor")
		return execResp, nil
	}

	return e.sendOTP(ctx, execResp)
}

// ValidatePrerequisites validates whether the prerequisites for the executor are met.
// If the mobile number is not available, it prompts the user for it.
func (e *mosipIDSendOTPExecutor) ValidatePrerequisites(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) bool {
	preReqMet := e.ExecutorInterface.ValidatePrerequisites(ctx, execResp)
	if preReqMet {
		return true
	}

	logger := e.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))
	logger.Debug("Prerequisites not met, prompting for individual ID input")

	execResp.Status = common.ExecUserInputRequired
	execResp.Inputs = []common.Input{IndividualIDInput}

	return false
}

// sendOTP sends an OTP to the user's mobile number by calling the MOSIP ID send-OTP API.
func (e *mosipIDSendOTPExecutor) sendOTP(ctx *core.NodeContext,
	execResp *common.ExecutorResponse) (*common.ExecutorResponse, error) {
	logger := e.logger.With(log.String(log.LoggerKeyFlowID, ctx.FlowID))

	username, err := e.getUsernameFromContext(ctx)
	if err != nil {
		return execResp, err
	}

	if execResp.Status == common.ExecFailure {
		return execResp, nil
	}

	identifiers := map[string]any{
		"username": username,
	}

	// Call AuthnProvider send-OTP API.
	metadata := buildAuthnMetadata(ctx)
	result, authnErr := e.mosipAuthnProvider.SendOTP(ctx.Context, identifiers, metadata)
	if authnErr != nil {
		logger.Error("Failed to send OTP via external API", log.Error(authnErr))
		return execResp, fmt.Errorf("failed to send OTP via external API: %w", authnErr)
	}

	execResp.ForwardedData["maskedEmail"] = result.MaskedEmail
	execResp.ForwardedData["maskedMobile"] = result.MaskedMobile
	execResp.Status = common.ExecComplete

	logger.Debug("External SMS OTP sent successfully")
	return execResp, nil
}

// getUsernameFromContext retrieves the user's username from the context.
func (e *mosipIDSendOTPExecutor) getUsernameFromContext(ctx *core.NodeContext) (string, error) {
	username := ctx.UserInputs[userAttributeUsername]
	if username == "" {
		username = ctx.RuntimeData[userAttributeUsername]
	}

	if username == "" && ctx.AuthenticatedUser.Attributes != nil {
		if id, ok := ctx.AuthenticatedUser.Attributes[userAttributeUsername]; ok {
			if idStr, valid := id.(string); valid && idStr != "" {
				username = idStr
			}
		}
	}

	if username == "" {
		return "", fmt.Errorf("username not found in context")
	}
	return username, nil
}

func buildAuthnMetadata(ctx *core.NodeContext) *authnprovider.AuthnMetadata {
	metadata := &authnprovider.AuthnMetadata{
		AppMetadata: make(map[string]interface{}),
	}

	// Copy application metadata if present
	if ctx.Application.Metadata != nil {
		for key, value := range ctx.Application.Metadata {
			metadata.AppMetadata[key] = value
		}
	}

	metadata.AppMetadata["app_id"] = ctx.AppID
	metadata.AppMetadata["transaction_id"] = ctx.FlowID

	// Extract client IDs from InboundAuthConfig
	var clientIDs []string
	for _, inboundConfig := range ctx.Application.InboundAuthConfig {
		if inboundConfig.OAuthAppConfig != nil && inboundConfig.OAuthAppConfig.ClientID != "" {
			clientIDs = append(clientIDs, inboundConfig.OAuthAppConfig.ClientID)
		}
	}

	// Add client IDs to metadata if present
	if len(clientIDs) > 0 {
		metadata.AppMetadata["client_ids"] = clientIDs
	}

	return metadata
}
