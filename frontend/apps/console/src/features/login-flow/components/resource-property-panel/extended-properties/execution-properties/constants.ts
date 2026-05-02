/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import {ExecutionTypes} from '@/features/flows/models/steps';
import type {IdentityProviderType} from '@/features/integrations/models/identity-provider';
import {IdentityProviderTypes} from '@/features/integrations/models/identity-provider';

/**
 * Maps executor names to their corresponding identity provider types.
 */
export const EXECUTOR_TO_IDP_TYPE_MAP: Record<string, IdentityProviderType> = {
  [ExecutionTypes.GoogleFederation]: IdentityProviderTypes.GOOGLE,
  [ExecutionTypes.GithubFederation]: IdentityProviderTypes.GITHUB,
  [ExecutionTypes.OAuthExecutor]: IdentityProviderTypes.OAUTH,
  [ExecutionTypes.OIDCAuthExecutor]: IdentityProviderTypes.OIDC,
};

/**
 * Set of federated executor names that support cross-OU and auth properties.
 */
export const FEDERATED_EXECUTORS = new Set<string>([
  ExecutionTypes.GoogleFederation,
  ExecutionTypes.GithubFederation,
  ExecutionTypes.OAuthExecutor,
  ExecutionTypes.OIDCAuthExecutor,
]);

/**
 * Available modes for SMS OTP executor.
 */
export const SMS_OTP_MODES = [
  {value: 'send', translationKey: 'flows:core.executions.smsOtp.mode.send', displayLabel: 'Send SMS OTP'},
  {value: 'verify', translationKey: 'flows:core.executions.smsOtp.mode.verify', displayLabel: 'Verify SMS OTP'},
] as const;

/**
 * Available modes for Identifying executor.
 */
export const IDENTIFYING_MODES = [
  {value: 'identify', translationKey: 'flows:core.executions.identifying.mode.identify', displayLabel: 'Identify User'},
  {value: 'resolve', translationKey: 'flows:core.executions.identifying.mode.resolve', displayLabel: 'Resolve User'},
] as const;

/**
 * Available modes for Passkey executor.
 */
export const PASSKEY_MODES = [
  {
    value: 'challenge',
    translationKey: 'flows:core.executions.passkey.mode.challenge',
    displayLabel: 'Request Passkey',
  },
  {value: 'verify', translationKey: 'flows:core.executions.passkey.mode.verify', displayLabel: 'Verify Passkey'},
  {
    value: 'register_start',
    translationKey: 'flows:core.executions.passkey.mode.registerStart',
    displayLabel: 'Start Passkey Registration',
  },
  {
    value: 'register_finish',
    translationKey: 'flows:core.executions.passkey.mode.registerFinish',
    displayLabel: 'Finish Passkey Registration',
  },
] as const;

/**
 * Available modes for Invite executor.
 */
export const INVITE_MODES = [
  {value: 'generate', translationKey: 'flows:core.executions.invite.mode.generate', displayLabel: 'Generate Invite'},
  {value: 'verify', translationKey: 'flows:core.executions.invite.mode.verify', displayLabel: 'Verify Invite'},
] as const;

/**
 * Available resolve strategies for OU Resolver executor.
 */
export const OU_RESOLVE_FROM_OPTIONS = [
  {value: 'caller', translationKey: 'flows:core.executions.ouResolver.resolveFrom.caller'},
  {value: 'prompt', translationKey: 'flows:core.executions.ouResolver.resolveFrom.prompt'},
  {value: 'promptAll', translationKey: 'flows:core.executions.ouResolver.resolveFrom.promptAll'},
] as const;

/**
 * Available HTTP methods for HTTP Request executor.
 */
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;

/**
 * Passkey modes that require relying party configuration.
 */
export const PASSKEY_MODES_WITH_RELYING_PARTY = ['challenge', 'register_start'] as const;
