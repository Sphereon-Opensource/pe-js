import fs from 'fs';

import { Optionality, PresentationSubmission } from '@sphereon/pex-models';

import { IVerifiableCredential, IVerifiablePresentation, Status } from '../../lib';
import { EvaluationClient, EvaluationClientWrapper } from '../../lib/evaluation';
import {
  InternalCredential,
  InternalPresentationDefinitionV1,
  WrappedVerifiableCredential,
} from '../../lib/types/Internal.types';
import { SSITypesBuilder } from '../../lib/types/SSITypesBuilder';

import { EvaluationClientWrapperData } from './EvaluationClientWrapperData';

function getFile(path: string) {
  return JSON.parse(fs.readFileSync(path, 'utf-8'));
}

const LIMIT_DISCLOSURE_SIGNATURE_SUITES = ['BbsBlsSignatureProof2020'];

const evaluationClientWrapperData: EvaluationClientWrapperData = new EvaluationClientWrapperData();

describe('evaluate', () => {
  it("should return error if uri in inputDescriptors doesn't match", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    pdSchema.input_descriptors[0].schema[0].uri = 'https://www.w3.org/TR/vc-data-model/#types1';
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.results[0]).toEqual(evaluationClientWrapperData.getInputDescriptorsDoesNotMatchResult0());
    expect(evaluationClient.results[5]).toEqual(evaluationClientWrapperData.getInputDescriptorsDoesNotMatchResult3());
    expect(evaluationResults.errors).toEqual(evaluationClientWrapperData.getError().errors);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it("should return ok if uri in vp matches at least one of input_descriptor's uris", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    pdSchema.input_descriptors[0].schema.push({ uri: 'https://www.w3.org/TR/vc-data-model/#types1' });
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const vc: IVerifiableCredential = vpSimple.verifiableCredential[0];
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vc]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const errorResults = evaluationClient.results.filter((result) => result.status === Status.ERROR);
    expect(errorResults.length).toEqual(0);
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getSuccess().value);
    expect(evaluationResults.errors?.length).toEqual(0);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it("should return error if uri in verifiableCredential doesn't match", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    (<IVerifiableCredential>vpSimple.verifiableCredential[0])['@context' as keyof IVerifiableCredential] = [
      'https://www.w3.org/TR/vc-data-model/#types1',
    ];
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.results[0]).toEqual(
      evaluationClientWrapperData.getUriInVerifiableCredentialDoesNotMatchResult0()
    );
    expect(evaluationClient.results[5]).toEqual(
      evaluationClientWrapperData.getUriInVerifiableCredentialDoesNotMatchResult3()
    );
    expect(evaluationResults.errors).toEqual(evaluationClientWrapperData.getError().errors);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it("should return error if all the uris in vp don't match at least one of input_descriptor's uris", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    (<IVerifiableCredential>vpSimple.verifiableCredential[0])['@context' as keyof IVerifiableCredential] = [
      'https://www.w3.org/TR/vc-data-model/#types1',
    ];
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const errorResults = evaluationClient.results.filter((result) => result.status === Status.ERROR);
    expect(errorResults.length).toEqual(2);
    expect(evaluationResults.errors).toEqual(evaluationClientWrapperData.getError().errors);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it("should return ok if all the uris in vp match at least one of input_descriptor's uris", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    pdSchema.input_descriptors[0].schema.push({ uri: 'https://www.w3.org/TR/vc-data-model/#types1' });
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const errorResults = evaluationClient.results.filter((result) => result.status === Status.ERROR);
    expect(errorResults.length).toEqual(0);
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getSuccess().value);
    expect(evaluationResults.errors?.length).toEqual(0);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it('should return info if limit_disclosure deletes the etc field', function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.wrappedVcs[0].internalCredential.credentialSubject['etc']).toBeUndefined();
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getSuccess().value);
    expect(evaluationResults.errors).toEqual(evaluationClientWrapperData.getSuccess().errors);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it('should return info if limit_disclosure does not delete the etc field', function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    delete pdSchema!.input_descriptors![0]!.constraints!.limit_disclosure;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.wrappedVcs[0].internalCredential.credentialSubject['etc']).toEqual('etc');
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getSuccess().value);
    expect(evaluationResults.errors).toEqual(evaluationClientWrapperData.getSuccess().errors);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it('should return warn if limit_disclosure deletes the etc field', function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-simple-age-predicate.json');
    pdSchema!.input_descriptors![0]!.constraints!.limit_disclosure = Optionality.Preferred;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.wrappedVcs[0].internalCredential.credentialSubject['etc']).toBeUndefined();
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getWarn().value);
    expect(evaluationResults.errors?.length).toEqual(0);
    expect(evaluationResults.warnings).toEqual(evaluationClientWrapperData.getWarn().warnings);
  });

  it("should return ok if vc[0] doesn't have the birthPlace field", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-schema-multiple-constraints.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile('./test/dif_pe_examples/vp/vp-multiple-constraints.json');
    pdSchema.input_descriptors[0].schema.push({ uri: 'https://www.w3.org/2018/credentials/v1' });
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.wrappedVcs[0].internalCredential.credentialSubject['birthPlace']).toBeUndefined();
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getSuccess().value);
    expect(evaluationResults.errors?.length).toEqual(0);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it("should return ok if vc[0] doesn't have the etc field", function () {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/dif_pe_examples/pdV1/pd-simple-schema-age-predicate.json'
    ).presentation_definition;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const vpSimple: IVerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp-simple-age-predicate.json'
    ) as IVerifiablePresentation;
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const evaluationClient: EvaluationClient = evaluationClientWrapper.getEvaluationClient();
    vpSimple!.holder = evaluationClientWrapperData.getHolderDID()[0];
    const evaluationResults = evaluationClientWrapper.evaluate(
      pd,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([vpSimple.verifiableCredential[0]]),
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    expect(evaluationClient.wrappedVcs[0].internalCredential.credentialSubject['etc']).toBeUndefined();
    expect(evaluationResults.value).toEqual(evaluationClientWrapperData.getSuccess().value);
    expect(evaluationResults.errors?.length).toEqual(0);
    expect(evaluationResults.warnings?.length).toEqual(0);
  });

  it('Evaluate submission requirements all rule', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/resources/sr_rules.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as IVerifiablePresentation;
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![0]];
    pdSchema!.input_descriptors = [pdSchema!.input_descriptors![0]];
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    evaluationClientWrapper.evaluate(
      pd,
      wvcs,
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const result: PresentationSubmission = evaluationClientWrapper.submissionFrom(pd, wvcs);
    expect(result.descriptor_map).toEqual(
      expect.objectContaining(evaluationClientWrapperData.getForSubmissionRequirementsAllRuleResult0().descriptor_map)
    );
    expect(result.definition_id).toEqual(
      evaluationClientWrapperData.getForSubmissionRequirementsAllRuleResult0().definition_id
    );
  });

  it('Evaluate submission requirements pick rule', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/resources/sr_rules.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as IVerifiablePresentation;
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![1]];
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    vpSimple!.holder = evaluationClientWrapperData.getHolderDID()[0];
    (vpSimple.verifiableCredential[0] as InternalCredential).issuer = 'did:foo:123';
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    evaluationClientWrapper.evaluate(
      pd,
      wvcs,
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const result: PresentationSubmission = evaluationClientWrapper.submissionFrom(pd, wvcs);
    expect(result).toEqual(
      expect.objectContaining({
        definition_id: '32f54163-7166-48f1-93d8-ff217bdb0653',
        descriptor_map: [
          {
            format: 'ldp_vc',
            id: 'Educational transcripts 1',
            path: '$.verifiableCredential[1]',
          },
          {
            format: 'ldp_vc',
            id: 'Educational transcripts 2',
            path: '$.verifiableCredential[2]',
          },
        ],
      })
    );
  });

  it('Create Presentation Submission from user selected credentials (max 1 from B)', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/resources/sr_rules.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as IVerifiablePresentation;
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![5]];
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    vpSimple!.holder = evaluationClientWrapperData.getHolderDID()[0];
    (vpSimple.verifiableCredential[0] as InternalCredential).issuer = 'did:foo:123';
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    evaluationClientWrapper.evaluate(
      pd,
      wvcs,
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const result: PresentationSubmission = evaluationClientWrapper.submissionFrom(pd, [wvcs[1]]);
    expect(result).toEqual(
      expect.objectContaining({
        definition_id: '32f54163-7166-48f1-93d8-ff217bdb0653',
        descriptor_map: [{ format: 'ldp_vc', id: 'Educational transcripts 1', path: '$.verifiableCredential[0]' }],
      })
    );
  });

  it('Create Presentation Submission without submission requirements', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFile(
      './test/resources/sr_rules.json'
    ).presentation_definition;
    const vpSimple: IVerifiablePresentation = getFile(
      './test/dif_pe_examples/vp/vp_general.json'
    ) as IVerifiablePresentation;
    delete pdSchema!.submission_requirements;
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(pdSchema);
    (vpSimple.verifiableCredential[0] as InternalCredential).issuer = 'did:foo:123';
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    vpSimple!.holder = evaluationClientWrapperData.getHolderDID()[0];
    evaluationClientWrapper.evaluate(
      pd,
      wvcs,
      evaluationClientWrapperData.getHolderDID(),
      LIMIT_DISCLOSURE_SIGNATURE_SUITES
    );
    const result: PresentationSubmission = evaluationClientWrapper.submissionFrom(pd, [wvcs[1], wvcs[2]]);
    expect(result).toEqual(
      expect.objectContaining({
        definition_id: '32f54163-7166-48f1-93d8-ff217bdb0653',
        descriptor_map: [
          {
            format: 'ldp_vc',
            id: 'Educational transcripts 1',
            path: '$.verifiableCredential[0]',
          },
          {
            format: 'ldp_vc',
            id: 'Educational transcripts 2',
            path: '$.verifiableCredential[1]',
          },
        ],
      })
    );
  });
  it('should map successfully the links from selectable credentials to verifiable credentials.', () => {
    const selectResults = evaluationClientWrapperData.getSelectResults();
    new EvaluationClientWrapper().fillSelectableCredentialsToVerifiableCredentialsMapping(
      selectResults,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(
        evaluationClientWrapperData.getVerifiableCredential()
      )
    );
    const verifiableCredential = selectResults.verifiableCredential![0];
    const indexInResults = selectResults.vcIndexes![0];
    expect(verifiableCredential['id' as keyof IVerifiableCredential]).toEqual(
      (<InternalCredential>evaluationClientWrapperData.getVerifiableCredential()[indexInResults]).id
    );
  });
});
