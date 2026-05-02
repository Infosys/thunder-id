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

import {useMemo, type ReactNode} from 'react';
import ConsentProperties from './execution-properties/ConsentProperties';
import {EXECUTOR_TO_IDP_TYPE_MAP} from './execution-properties/constants';
import EmailProperties from './execution-properties/EmailProperties';
import FederationProperties from './execution-properties/FederationProperties';
import HttpRequestProperties from './execution-properties/HttpRequestProperties';
import IdentifyingProperties from './execution-properties/IdentifyingProperties';
import InviteProperties from './execution-properties/InviteProperties';
import NoConfigProperties from './execution-properties/NoConfigProperties';
import OUExecutorProperties from './execution-properties/OUExecutorProperties';
import OUResolverProperties from './execution-properties/OUResolverProperties';
import PasskeyProperties from './execution-properties/PasskeyProperties';
import PermissionValidatorProperties from './execution-properties/PermissionValidatorProperties';
import ProvisioningProperties from './execution-properties/ProvisioningProperties';
import SmsOtpProperties from './execution-properties/SmsOtpProperties';
import SmsProperties from './execution-properties/SmsProperties';
import UserTypeResolverProperties from './execution-properties/UserTypeResolverProperties';
import type {CommonResourcePropertiesPropsInterface} from '@/features/flows/components/resource-property-panel/ResourceProperties';
import {ExecutionTypes} from '@/features/flows/models/steps';
import type {StepData} from '@/features/flows/models/steps';

/**
 * Props interface of {@link ExecutionExtendedProperties}
 */
export type ExecutionExtendedPropertiesPropsInterface = CommonResourcePropertiesPropsInterface;

/**
 * Extended properties for execution step elements.
 * Routes to the appropriate sub-component based on executor type.
 *
 * @param props - Props injected to the component.
 * @returns The ExecutionExtendedProperties component.
 */
function ExecutionExtendedProperties({resource, onChange}: ExecutionExtendedPropertiesPropsInterface): ReactNode {
  const executorName = useMemo(() => {
    const stepData = resource?.data as StepData | undefined;
    return stepData?.action?.executor?.name;
  }, [resource]);

  if (!executorName) {
    return null;
  }

  switch (executorName) {
    case ExecutionTypes.SMSOTPAuth:
      return <SmsOtpProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.ConsentExecutor:
      return <ConsentProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.IdentifyingExecutor:
      return <IdentifyingProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.PasskeyAuth:
      return <PasskeyProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.OUResolverExecutor:
      return <OUResolverProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.InviteExecutor:
      return <InviteProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.EmailExecutor:
      return <EmailProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.SMSExecutor:
      return <SmsProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.PermissionValidator:
      return <PermissionValidatorProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.ProvisioningExecutor:
      return <ProvisioningProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.OUExecutor:
      return <OUExecutorProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.UserTypeResolver:
      return <UserTypeResolverProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.HTTPRequestExecutor:
      return <HttpRequestProperties resource={resource} onChange={onChange} />;
    case ExecutionTypes.CredentialSetter:
    case ExecutionTypes.AttributeUniquenessValidator:
    case ExecutionTypes.MagicLinkExecutor:
      return <NoConfigProperties />;
    default:
      break;
  }

  // Federated executors (Google, GitHub, OAuth, OIDC) - check if executor has an IDP type mapping
  if (EXECUTOR_TO_IDP_TYPE_MAP[executorName]) {
    return <FederationProperties resource={resource} onChange={onChange} />;
  }

  return null;
}

export default ExecutionExtendedProperties;
