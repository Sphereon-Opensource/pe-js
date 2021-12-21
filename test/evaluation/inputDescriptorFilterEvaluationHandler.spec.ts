import fs from 'fs';

import { PresentationSubmission } from '@sphereon/pe-models';

import {
  EvaluationClient,
  EvaluationHandler,
  HandlerCheckResult,
  InternalVerifiableCredential,
  Status,
  VerifiablePresentation,
} from '../../lib';
import { InputDescriptorFilterEvaluationHandler } from '../../lib/evaluation/handlers';
import PEMessages from '../../lib/types/Messages';
import { InternalPresentationDefinitionV1 } from '../../lib/types/SSI.types';
import { SSITypesBuilder } from '../../lib/types/SSITypesBuilder';

const message: HandlerCheckResult = {
  input_descriptor_path: `$.input_descriptors[0]`,
  verifiable_credential_path: `$[0]`,
  evaluator: `FilterEvaluation`,
  status: Status.INFO,
  payload: { result: { path: ['$', 'vc', 'issuer'], value: 'did:example:123' }, valid: true },
  message: PEMessages.INPUT_CANDIDATE_IS_ELIGIBLE_FOR_PRESENTATION_SUBMISSION,
};

function getFile(
  path: string
): InternalPresentationDefinitionV1 | VerifiablePresentation | InternalVerifiableCredential {
  const file = JSON.parse(fs.readFileSync(path, 'utf-8'));
  if (Object.keys(file).includes('presentation_definition')) {
    return file.presentation_definition as InternalPresentationDefinitionV1;
  } else if (Object.keys(file).includes('presentation_submission')) {
    return file as VerifiablePresentation;
  } else {
    return file as InternalVerifiableCredential;
  }
}

describe('inputDescriptorFilterEvaluationHandler tests', () => {
  it(`input descriptor's constraint property missing`, () => {
    const presentation: VerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as VerifiablePresentation;
    const presentationDefinition: InternalPresentationDefinitionV1 = getFile(
      './test/resources/pd_input_descriptor_filter.json'
    ) as InternalPresentationDefinitionV1;
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[0]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]'))
    );
    const message0 = { ...message };
    message0.input_descriptor_path = '$.input_descriptors[0]';
    message0.payload = { result: [], valid: true };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: [], valid: true };
    const message2 = { ...message1, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: [], valid: true };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.verifiableCredential = SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(
      presentation.verifiableCredential
    );
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(presentation.verifiableCredential)
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields property missing`, () => {
    const presentation: VerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as VerifiablePresentation;
    const presentationDefinition: InternalPresentationDefinitionV1 = getFile(
      './test/resources/pd_input_descriptor_filter.json'
    ) as InternalPresentationDefinitionV1;
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[1]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]'))
    );
    const message0 = { ...message };
    message0.input_descriptor_path = '$.input_descriptors[0]';
    message0.payload = { result: [], valid: true };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: [], valid: true };
    const message2 = { ...message1, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: [], valid: true };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.verifiableCredential = SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(
      presentation.verifiableCredential
    );
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(presentation.verifiableCredential)
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields.length is equal to 0`, () => {
    const presentation: VerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as VerifiablePresentation;
    const presentationDefinition: InternalPresentationDefinitionV1 = getFile(
      './test/resources/pd_input_descriptor_filter.json'
    ) as InternalPresentationDefinitionV1;
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[2]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]'))
    );
    const message0 = { ...message };
    message0.input_descriptor_path = '$.input_descriptors[0]';
    message0.payload = { result: [], valid: true };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: [], valid: true };
    const message2 = { ...message1, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: [], valid: true };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.verifiableCredential = SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(
      presentation.verifiableCredential
    );
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(presentation.verifiableCredential)
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields.path does not match`, () => {
    const presentation: VerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as VerifiablePresentation;
    const presentationDefinition: InternalPresentationDefinitionV1 = getFile(
      './test/resources/pd_input_descriptor_filter.json'
    ) as InternalPresentationDefinitionV1;
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[3]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]'))
    );
    const message0 = {
      ...message,
      ['status']: Status.ERROR,
      ['message']: PEMessages.INPUT_CANDIDATE_DOESNT_CONTAIN_PROPERTY,
    };
    message0.payload = { valid: false };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { valid: false };
    const message2 = { ...message0, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { valid: false };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.verifiableCredential = SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(
      presentation.verifiableCredential
    );
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(presentation.verifiableCredential)
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields.filter does not match`, () => {
    const presentation: VerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as VerifiablePresentation;
    const presentationDefinition: InternalPresentationDefinitionV1 = getFile(
      './test/resources/pd_input_descriptor_filter.json'
    ) as InternalPresentationDefinitionV1;
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[4]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]'))
    );
    const message0 = {
      ...message,
      ['status']: Status.ERROR,
      ['message']: PEMessages.INPUT_CANDIDATE_FAILED_FILTER_EVALUATION,
    };
    message0.payload = { result: { path: ['$', 'vc', 'issuer'], value: 'did:example:123' }, valid: false };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: false };
    const message2 = { ...message0, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: false };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.verifiableCredential = SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(
      presentation.verifiableCredential
    );
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(presentation.verifiableCredential)
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraint.fields.filter match`, () => {
    const presentation: VerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as VerifiablePresentation;
    const presentationDefinition: InternalPresentationDefinitionV1 = getFile(
      './test/resources/pd_input_descriptor_filter.json'
    ) as InternalPresentationDefinitionV1;
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[5]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]'))
    );
    const message1 = { ...message, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: true };
    const message2 = { ...message, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: true };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.verifiableCredential = SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(
      presentation.verifiableCredential
    );
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToInternal(presentation.verifiableCredential)
    );
    expect(evaluationClient.results).toEqual([message, message1, message2]);
  });
});
