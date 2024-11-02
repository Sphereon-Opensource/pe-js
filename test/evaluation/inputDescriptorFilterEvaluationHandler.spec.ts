import { PresentationSubmission } from '@sphereon/pex-models';
import { IVerifiablePresentation } from '@sphereon/ssi-types';

import { HandlerCheckResult, Status } from '../../lib';
import { EvaluationClient, EvaluationHandler } from '../../lib/evaluation';
import { InputDescriptorFilterEvaluationHandler } from '../../lib/evaluation/handlers';
import { InternalPresentationDefinitionV1 } from '../../lib/types';
import { SSITypesBuilder } from '../../lib/types';
import PexMessages from '../../lib/types/Messages';
import { getFileAsEntity } from '../utils/files';

const message: HandlerCheckResult = {
  input_descriptor_path: `$.input_descriptors[0]`,
  verifiable_credential_path: `$[0]`,
  evaluator: `FilterEvaluation`,
  status: Status.INFO,
  payload: { result: { path: ['$', 'vc', 'issuer'], value: 'did:example:123' }, valid: true, format: 'jwt_vc' },
  message: PexMessages.INPUT_CANDIDATE_IS_ELIGIBLE_FOR_PRESENTATION_SUBMISSION,
};

describe('inputDescriptorFilterEvaluationHandler tests', () => {
  it(`input descriptor's constraint property missing`, () => {
    const presentation: IVerifiablePresentation = getFileAsEntity<IVerifiablePresentation>('./test/dif_pe_examples/vp/vp_general.json');
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_input_descriptor_filter.json');
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[0]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]')),
    );
    const message0 = { ...message };
    message0.input_descriptor_path = '$.input_descriptors[0]';
    message0.payload = { result: [], valid: true, format: 'jwt_vc' };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: [], valid: true, format: 'ldp_vc' };
    const message2 = { ...message1, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: [], valid: true, format: 'ldp_vc' };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields property missing`, () => {
    const presentation = getFileAsEntity<IVerifiablePresentation>('./test/dif_pe_examples/vp/vp_general.json');
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_input_descriptor_filter.json');
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[1]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]')),
    );
    const message0 = { ...message };
    message0.input_descriptor_path = '$.input_descriptors[0]';
    message0.payload = { result: [], valid: true, format: 'jwt_vc' };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: [], valid: true, format: 'ldp_vc' };
    const message2 = { ...message1, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: [], valid: true, format: 'ldp_vc' };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields.length is equal to 0`, () => {
    const presentation = getFileAsEntity<IVerifiablePresentation>('./test/dif_pe_examples/vp/vp_general.json');
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_input_descriptor_filter.json');
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[2]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]')),
    );
    const message0 = { ...message };
    message0.input_descriptor_path = '$.input_descriptors[0]';
    message0.payload = { result: [], valid: true, format: 'jwt_vc' };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: [], valid: true, format: 'ldp_vc' };
    const message2 = { ...message1, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: [], valid: true, format: 'ldp_vc' };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields.path does not match`, () => {
    const presentation = getFileAsEntity<IVerifiablePresentation>('./test/dif_pe_examples/vp/vp_general.json');
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_input_descriptor_filter.json');
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[3]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]')),
    );
    const message0 = {
      ...message,
      ['status']: Status.ERROR,
      ['message']: PexMessages.INPUT_CANDIDATE_DOESNT_CONTAIN_PROPERTY,
    };
    message0.payload = { valid: false, format: 'jwt_vc' };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { valid: false, format: 'ldp_vc' };
    const message2 = { ...message0, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { valid: false, format: 'ldp_vc' };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraints.fields.filter does not match`, () => {
    const presentation = getFileAsEntity<IVerifiablePresentation>('./test/dif_pe_examples/vp/vp_general.json');
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_input_descriptor_filter.json');
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[4]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]')),
    );
    const message0 = {
      ...message,
      ['status']: Status.ERROR,
      ['message']: PexMessages.INPUT_CANDIDATE_FAILED_FILTER_EVALUATION,
    };
    message0.payload = { result: { path: ['$', 'vc', 'issuer'], value: 'did:example:123' }, valid: false, format: 'jwt_vc' };
    const message1 = { ...message0, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: false, format: 'ldp_vc' };
    const message2 = { ...message0, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: false, format: 'ldp_vc' };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationClient.results).toEqual([message0, message1, message2]);
  });

  it(`input descriptor's constraint.fields.filter match`, () => {
    const presentation = getFileAsEntity<IVerifiablePresentation>('./test/dif_pe_examples/vp/vp_general.json');
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_input_descriptor_filter.json');
    presentationDefinition.input_descriptors = [presentationDefinition.input_descriptors[5]];
    presentation.presentation_submission?.descriptor_map.forEach(
      (d, i, dm) => (dm[i].path = d.path.replace(/\$\.verifiableCredential\[(\d+)/g, '$[$1]')),
    );
    const message1 = { ...message, ['verifiable_credential_path']: '$[1]' };
    message1.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: true, format: 'ldp_vc' };
    const message2 = { ...message, ['verifiable_credential_path']: '$[2]' };
    message2.payload = { result: { path: ['$', 'issuer'], value: 'did:foo:123' }, valid: true, format: 'ldp_vc' };
    const evaluationClient: EvaluationClient = new EvaluationClient();
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    const evaluationHandler: EvaluationHandler = new InputDescriptorFilterEvaluationHandler(evaluationClient);
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationClient.results).toEqual([message, message1, message2]);
  });
});
