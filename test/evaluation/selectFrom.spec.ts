import { createHash } from 'crypto';
import fs from 'fs';

import { SDJwt } from '@sd-jwt/core';
import { IVerifiableCredential, WrappedVerifiableCredential } from '@sphereon/ssi-types';

import { PEX, Status } from '../../lib';
import { EvaluationClientWrapper } from '../../lib/evaluation';
import { SubmissionRequirementMatchType } from '../../lib/evaluation/core';
import { InternalPresentationDefinitionV1, InternalPresentationDefinitionV2, SSITypesBuilder } from '../../lib/types';
import PexMessages from '../../lib/types/Messages';
import { ClaimValue } from '../types';

export const hasher = (data: string) => createHash('sha256').update(data).digest();

function getFile(path: string) {
  return fs.readFileSync(path, 'utf-8');
}

function getFileAsJson(path: string) {
  return JSON.parse(getFile(path));
}

const dids = ['did:example:ebfeb1f712ebc6f1c276e12ec21'];

const LIMIT_DISCLOSURE_SIGNATURE_SUITES = ['BbsBlsSignatureProof2020'];

const pex = new PEX({
  hasher,
});

describe('selectFrom tests', () => {
  it('Evaluate submission requirements all from group A', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![0]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    expect(
      evaluationClientWrapper.selectFrom(pd, wvcs, {
        holderDIDs: dids,
        limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
      }),
    ).toEqual({
      areRequiredCredentialsPresent: Status.INFO,
      errors: [],
      matches: [
        {
          from: 'A',
          name: 'Submission of educational transcripts',
          id: 0,
          areRequiredCredentialsPresent: Status.INFO,
          rule: {
            type: 'all',
            count: 3,
          },
          input_descriptors: [
            {
              areRequiredCredentialsPresent: Status.INFO,
              id: 'Educational transcripts',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[0]'],
            },
            {
              areRequiredCredentialsPresent: Status.INFO,
              id: 'Educational transcripts 1',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[1]'],
            },
            {
              areRequiredCredentialsPresent: Status.INFO,
              id: 'Educational transcripts 2',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[2]'],
            },
          ],
          type: SubmissionRequirementMatchType.SubmissionRequirement,
        },
      ],
      verifiableCredential: [vpSimple.verifiableCredential[0], vpSimple.verifiableCredential[1], vpSimple.verifiableCredential[2]],
      warnings: [],
      vcIndexes: [0, 1, 2],
    });
  });

  it('Evaluate without submission requirements', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    delete pdSchema.submission_requirements;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.matches?.length).toBe(3);
    expect(result.areRequiredCredentialsPresent).toBe(Status.INFO);
  });

  it('Evaluate submission requirements min 2 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![1]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    expect(
      evaluationClientWrapper.selectFrom(pd, wvcs, {
        holderDIDs: dids,
        limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
      }),
    ).toEqual({
      areRequiredCredentialsPresent: Status.INFO,
      errors: [],
      matches: [
        {
          id: 0,
          name: 'Eligibility to Work Proof',
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from: 'B',
          areRequiredCredentialsPresent: Status.INFO,
          rule: {
            type: 'pick',
            min: 2,
          },
          input_descriptors: [
            {
              id: 'Educational transcripts 1',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[0]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
            {
              id: 'Educational transcripts 2',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[1]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
          ],
        },
      ],
      verifiableCredential: [vpSimple.verifiableCredential[1], vpSimple.verifiableCredential[2]],
      warnings: [],
      vcIndexes: [1, 2],
    });
  });

  it('Evaluate submission requirements either all from group A or 2 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![2]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.areRequiredCredentialsPresent).toEqual(Status.WARN);
    expect(result.errors?.length).toEqual(16);
  });

  it('Evaluate submission requirements max 2 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![3]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    expect(
      evaluationClientWrapper.selectFrom(pd, wvcs, {
        holderDIDs: dids,
        limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
      }),
    ).toEqual({
      areRequiredCredentialsPresent: Status.INFO,
      errors: [],
      matches: [
        {
          id: 0,
          name: 'Eligibility to Work Proof',
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from: 'B',
          areRequiredCredentialsPresent: Status.INFO,
          rule: {
            type: 'pick',
            max: 2,
          },
          input_descriptors: [
            {
              id: 'Educational transcripts 1',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[0]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
            {
              id: 'Educational transcripts 2',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[1]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
          ],
        },
      ],
      verifiableCredential: [vpSimple.verifiableCredential[1], vpSimple.verifiableCredential[2]],
      warnings: [],
      vcIndexes: [1, 2],
    });
  });

  it('Evaluate submission requirements all from group A and 2 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![8]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    expect(
      evaluationClientWrapper.selectFrom(pd, wvcs, {
        holderDIDs: dids,
        limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
      }),
    ).toEqual({
      areRequiredCredentialsPresent: Status.INFO,
      errors: [],
      matches: [
        {
          id: 0,
          areRequiredCredentialsPresent: Status.INFO,
          name: 'Confirm banking relationship or employment and residence proofs',
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from_nested: [
            {
              id: 0,
              type: SubmissionRequirementMatchType.SubmissionRequirement,
              from: 'A',
              areRequiredCredentialsPresent: Status.INFO,
              rule: {
                type: 'all',
                count: 3,
              },
              input_descriptors: [
                {
                  id: 'Educational transcripts',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[0]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 1',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[1]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 2',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[2]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
              ],
            },
            {
              id: 1,
              type: SubmissionRequirementMatchType.SubmissionRequirement,
              from: 'B',
              areRequiredCredentialsPresent: Status.INFO,
              rule: {
                type: 'pick',
                count: 2,
              },
              input_descriptors: [
                {
                  id: 'Educational transcripts 1',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[1]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 2',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[2]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
              ],
            },
          ],
          rule: {
            type: 'all',
            count: 2,
          },
        },
      ],
      verifiableCredential: [vpSimple.verifiableCredential[0], vpSimple.verifiableCredential[1], vpSimple.verifiableCredential[2]],
      warnings: [],
      vcIndexes: [0, 1, 2],
    });
  });

  it('Evaluate submission requirements min 1: (all from group A or 2 from group B)', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![9]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    expect(
      evaluationClientWrapper.selectFrom(pd, wvcs, {
        holderDIDs: dids,
        limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
      }),
    ).toEqual({
      areRequiredCredentialsPresent: Status.INFO,
      errors: [],
      matches: [
        {
          id: 0,
          areRequiredCredentialsPresent: Status.INFO,
          name: 'Confirm banking relationship or employment and residence proofs',
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from_nested: [
            {
              id: 0,
              type: SubmissionRequirementMatchType.SubmissionRequirement,
              from: 'A',
              areRequiredCredentialsPresent: Status.INFO,
              rule: {
                type: 'all',
                count: 3,
              },
              input_descriptors: [
                {
                  id: 'Educational transcripts',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[0]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 1',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[1]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 2',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[2]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
              ],
            },
            {
              id: 1,
              type: SubmissionRequirementMatchType.SubmissionRequirement,
              from: 'B',
              areRequiredCredentialsPresent: Status.INFO,
              rule: {
                type: 'pick',
                count: 2,
              },
              input_descriptors: [
                {
                  id: 'Educational transcripts 1',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[1]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 2',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[2]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
              ],
            },
          ],
          rule: {
            type: 'pick',
            min: 1,
          },
        },
      ],
      verifiableCredential: [vpSimple.verifiableCredential[0], vpSimple.verifiableCredential[1], vpSimple.verifiableCredential[2]],
      warnings: [],
      vcIndexes: [0, 1, 2],
    });
  });

  it('Evaluate submission requirements max 2: (all from group A and 2 from group B)', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![10]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    expect(
      evaluationClientWrapper.selectFrom(pd, wvcs, {
        holderDIDs: dids,
        limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
      }),
    ).toEqual({
      errors: [],
      matches: [
        {
          id: 0,
          areRequiredCredentialsPresent: Status.INFO,
          name: 'Confirm banking relationship or employment and residence proofs',
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from_nested: [
            {
              id: 0,
              type: SubmissionRequirementMatchType.SubmissionRequirement,
              from: 'A',
              areRequiredCredentialsPresent: Status.INFO,
              rule: {
                type: 'all',
                count: 3,
              },
              input_descriptors: [
                {
                  id: 'Educational transcripts',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[0]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 1',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[1]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 2',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[2]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
              ],
            },
            {
              id: 1,
              type: SubmissionRequirementMatchType.SubmissionRequirement,
              from: 'B',
              areRequiredCredentialsPresent: Status.INFO,
              rule: {
                type: 'pick',
                count: 2,
              },
              input_descriptors: [
                {
                  id: 'Educational transcripts 1',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[1]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
                {
                  id: 'Educational transcripts 2',
                  name: 'Submission of educational transcripts',
                  type: SubmissionRequirementMatchType.InputDescriptor,
                  vc_path: ['$.verifiableCredential[2]'],
                  areRequiredCredentialsPresent: Status.INFO,
                },
              ],
            },
          ],
          rule: {
            type: 'pick',
            max: 2,
          },
        },
      ],
      areRequiredCredentialsPresent: Status.INFO,
      verifiableCredential: [vpSimple.verifiableCredential[0], vpSimple.verifiableCredential[1], vpSimple.verifiableCredential[2]],
      warnings: [],
      vcIndexes: [0, 1, 2],
    });
  });

  it('Evaluate submission requirements min 3 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![4]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.areRequiredCredentialsPresent).toBe(Status.ERROR);
    expect(result.errors).toEqual([
      {
        tag: 'UriEvaluation',
        status: 'error',
        message: PexMessages.URI_EVALUATION_DIDNT_PASS + ': $.input_descriptors[0]: $.verifiableCredential[1]',
      },
      {
        tag: 'UriEvaluation',
        status: 'error',
        message: PexMessages.URI_EVALUATION_DIDNT_PASS + ': $.input_descriptors[0]: $.verifiableCredential[2]',
      },
      {
        tag: 'UriEvaluation',
        status: 'error',
        message: PexMessages.URI_EVALUATION_DIDNT_PASS + ': $.input_descriptors[1]: $.verifiableCredential[0]',
      },
      {
        tag: 'UriEvaluation',
        status: 'error',
        message: PexMessages.URI_EVALUATION_DIDNT_PASS + ': $.input_descriptors[1]: $.verifiableCredential[2]',
      },
      {
        tag: 'UriEvaluation',
        status: 'error',
        message: PexMessages.URI_EVALUATION_DIDNT_PASS + ': $.input_descriptors[2]: $.verifiableCredential[0]',
      },
      {
        tag: 'UriEvaluation',
        status: 'error',
        message: PexMessages.URI_EVALUATION_DIDNT_PASS + ': $.input_descriptors[2]: $.verifiableCredential[1]',
      },
      {
        tag: 'FilterEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_FAILED_FILTER_EVALUATION + ': $.input_descriptors[1]: $.verifiableCredential[0]',
      },
      {
        tag: 'FilterEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_FAILED_FILTER_EVALUATION + ': $.input_descriptors[2]: $.verifiableCredential[0]',
      },
      {
        tag: 'FilterEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_FAILED_FILTER_EVALUATION + ': $.input_descriptors[0]: $.verifiableCredential[1]',
      },
      {
        tag: 'FilterEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_FAILED_FILTER_EVALUATION + ': $.input_descriptors[0]: $.verifiableCredential[2]',
      },
      {
        tag: 'MarkForSubmissionEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_IS_NOT_ELIGIBLE_FOR_PRESENTATION_SUBMISSION + ': $.input_descriptors[0]: $.verifiableCredential[1]',
      },
      {
        tag: 'MarkForSubmissionEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_IS_NOT_ELIGIBLE_FOR_PRESENTATION_SUBMISSION + ': $.input_descriptors[0]: $.verifiableCredential[2]',
      },
      {
        tag: 'MarkForSubmissionEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_IS_NOT_ELIGIBLE_FOR_PRESENTATION_SUBMISSION + ': $.input_descriptors[1]: $.verifiableCredential[0]',
      },
      {
        tag: 'MarkForSubmissionEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_IS_NOT_ELIGIBLE_FOR_PRESENTATION_SUBMISSION + ': $.input_descriptors[1]: $.verifiableCredential[2]',
      },
      {
        tag: 'MarkForSubmissionEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_IS_NOT_ELIGIBLE_FOR_PRESENTATION_SUBMISSION + ': $.input_descriptors[2]: $.verifiableCredential[0]',
      },
      {
        tag: 'MarkForSubmissionEvaluation',
        status: 'error',
        message: PexMessages.INPUT_CANDIDATE_IS_NOT_ELIGIBLE_FOR_PRESENTATION_SUBMISSION + ': $.input_descriptors[2]: $.verifiableCredential[1]',
      },
    ]);
    expect(result.matches).toEqual([
      {
        id: 0,
        name: 'Eligibility to Work Proof',
        type: SubmissionRequirementMatchType.SubmissionRequirement,
        from: 'B',
        areRequiredCredentialsPresent: Status.ERROR,
        rule: {
          type: 'pick',
          min: 3,
        },
        input_descriptors: [
          {
            id: 'Educational transcripts 1',
            name: 'Submission of educational transcripts',
            type: SubmissionRequirementMatchType.InputDescriptor,
            vc_path: ['$.verifiableCredential[0]'],
            areRequiredCredentialsPresent: Status.INFO,
          },
          {
            id: 'Educational transcripts 2',
            name: 'Submission of educational transcripts',
            type: SubmissionRequirementMatchType.InputDescriptor,
            vc_path: ['$.verifiableCredential[1]'],
            areRequiredCredentialsPresent: Status.INFO,
          },
        ],
      },
    ]);
  });

  it('Evaluate submission requirements max 1 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![5]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.matches).toEqual([
      {
        from: 'B',
        rule: {
          type: 'pick',
          max: 1,
        },
        areRequiredCredentialsPresent: Status.WARN,
        input_descriptors: [
          {
            areRequiredCredentialsPresent: Status.INFO,
            id: 'Educational transcripts 1',
            name: 'Submission of educational transcripts',
            type: SubmissionRequirementMatchType.InputDescriptor,
            vc_path: ['$.verifiableCredential[0]'],
          },
          {
            areRequiredCredentialsPresent: Status.INFO,
            id: 'Educational transcripts 2',
            name: 'Submission of educational transcripts',
            type: SubmissionRequirementMatchType.InputDescriptor,
            vc_path: ['$.verifiableCredential[1]'],
          },
        ],
        type: SubmissionRequirementMatchType.SubmissionRequirement,
        name: 'Eligibility to Work Proof',
        id: 0,
      },
    ]);
    expect(result.errors?.length).toEqual(16);
    expect(result.verifiableCredential?.length).toEqual(2);
    expect(result.areRequiredCredentialsPresent).toEqual(Status.WARN);
  });

  it('Evaluate submission requirements exactly 1 from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![6]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.matches?.length).toEqual(1);
    expect(result.verifiableCredential?.length).toEqual(2);
    expect(result.errors?.length).toEqual(16);
    expect(result.areRequiredCredentialsPresent).toEqual(Status.WARN);
  });

  it('Evaluate submission requirements all from group B', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![7]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.errors?.length).toEqual(0);
    expect(result.matches?.length).toEqual(1);
    expect(result.areRequiredCredentialsPresent).toEqual(Status.INFO);
    expect(result.verifiableCredential?.length).toEqual(2);
  });

  it('Evaluate submission requirements min 3: (all from group A or 2 from group B + unexistent)', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![11]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    pd.submission_requirements![0].min = 1;
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.areRequiredCredentialsPresent).toEqual(Status.INFO);
    expect(result.matches?.length).toEqual(1);
    expect(result.matches![0]).toEqual({
      id: 0,
      areRequiredCredentialsPresent: Status.INFO,
      name: 'Confirm banking relationship or employment and residence proofs',
      type: SubmissionRequirementMatchType.SubmissionRequirement,
      from_nested: [
        {
          id: 0,
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from: 'A',
          areRequiredCredentialsPresent: Status.INFO,
          rule: {
            type: 'all',
            count: 3,
          },
          input_descriptors: [
            {
              id: 'Educational transcripts',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[0]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
            {
              id: 'Educational transcripts 1',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[1]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
            {
              id: 'Educational transcripts 2',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[2]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
          ],
        },
        {
          id: 1,
          type: SubmissionRequirementMatchType.SubmissionRequirement,
          from: 'B',
          areRequiredCredentialsPresent: Status.INFO,
          rule: {
            type: 'pick',
            count: 2,
          },
          input_descriptors: [
            {
              id: 'Educational transcripts 1',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[1]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
            {
              id: 'Educational transcripts 2',
              name: 'Submission of educational transcripts',
              type: SubmissionRequirementMatchType.InputDescriptor,
              vc_path: ['$.verifiableCredential[2]'],
              areRequiredCredentialsPresent: Status.INFO,
            },
          ],
        },
      ],
      rule: {
        type: 'pick',
        min: 1,
      },
    });
  });

  it('Evaluate submission requirements max 1: (all from group A and 2 from group B)', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/resources/sr_rules.json').presentation_definition;
    const vpSimple = getFileAsJson('./test/dif_pe_examples/vp/vp_general.json');
    pdSchema!.submission_requirements = [pdSchema!.submission_requirements![12]];
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([
      vpSimple.verifiableCredential[0],
      vpSimple.verifiableCredential[1],
      vpSimple.verifiableCredential[2],
    ]);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: dids,
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.areRequiredCredentialsPresent).toEqual(Status.WARN);
    expect(result.matches).toEqual([
      {
        id: 0,
        areRequiredCredentialsPresent: Status.WARN,
        name: 'Confirm banking relationship or employment and residence proofs',
        type: SubmissionRequirementMatchType.SubmissionRequirement,
        from_nested: [
          {
            id: 0,
            type: SubmissionRequirementMatchType.SubmissionRequirement,
            from: 'A',
            areRequiredCredentialsPresent: Status.INFO,
            rule: {
              type: 'all',
              count: 3,
            },
            input_descriptors: [
              {
                id: 'Educational transcripts',
                name: 'Submission of educational transcripts',
                type: SubmissionRequirementMatchType.InputDescriptor,
                vc_path: ['$.verifiableCredential[0]'],
                areRequiredCredentialsPresent: Status.INFO,
              },
              {
                id: 'Educational transcripts 1',
                name: 'Submission of educational transcripts',
                type: SubmissionRequirementMatchType.InputDescriptor,
                vc_path: ['$.verifiableCredential[1]'],
                areRequiredCredentialsPresent: Status.INFO,
              },
              {
                id: 'Educational transcripts 2',
                name: 'Submission of educational transcripts',
                type: SubmissionRequirementMatchType.InputDescriptor,
                vc_path: ['$.verifiableCredential[2]'],
                areRequiredCredentialsPresent: Status.INFO,
              },
            ],
          },
          {
            id: 1,
            type: SubmissionRequirementMatchType.SubmissionRequirement,
            from: 'B',
            areRequiredCredentialsPresent: Status.INFO,
            rule: {
              type: 'pick',
              count: 2,
            },
            input_descriptors: [
              {
                id: 'Educational transcripts 1',
                name: 'Submission of educational transcripts',
                type: SubmissionRequirementMatchType.InputDescriptor,
                vc_path: ['$.verifiableCredential[1]'],
                areRequiredCredentialsPresent: Status.INFO,
              },
              {
                id: 'Educational transcripts 2',
                name: 'Submission of educational transcripts',
                type: SubmissionRequirementMatchType.InputDescriptor,
                vc_path: ['$.verifiableCredential[2]'],
                areRequiredCredentialsPresent: Status.INFO,
              },
            ],
          },
        ],
        rule: {
          type: 'pick',
          max: 1,
        },
      },
    ]);
    expect(result.errors?.length).toEqual(16);
  });

  it('Evaluate case without presentation submission', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson(
      './test/dif_pe_examples/pdV1/pd-PermanentResidentCard.json',
    ).presentation_definition;
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const verifiableCredential = getFileAsJson('./test/dif_pe_examples/vc/vc-PermanentResidentCard.json');
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([verifiableCredential]);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: ['FAsYneKJhWBP2n5E21ZzdY'],
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result!.errors!.length).toEqual(0);
    expect(result!.matches![0]!.name).toEqual("EU Driver's License");
    expect(result!.matches![0]).toEqual({
      name: "EU Driver's License",
      id: 'citizenship_input_1',
      type: SubmissionRequirementMatchType.InputDescriptor,
      areRequiredCredentialsPresent: Status.INFO,
      vc_path: ['$.verifiableCredential[0]'],
    });
  });

  it('Evaluate driver license name result', () => {
    const pdSchema: InternalPresentationDefinitionV1 = getFileAsJson('./test/dif_pe_examples/pdV1/pd_driver_license_name.json')
      .presentation_definition as InternalPresentationDefinitionV1;
    const pd = SSITypesBuilder.modelEntityToInternalPresentationDefinitionV1(pdSchema);
    const verifiableCredential: IVerifiableCredential = getFileAsJson(
      './test/dif_pe_examples/vc/vc-PermanentResidentCard.json',
    ) as IVerifiableCredential;
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs([verifiableCredential]);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: ['FAsYneKJhWBP2n5E21ZzdY'],
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result!.errors!.length).toEqual(0);
    expect(result!.matches![0]!.name).toEqual("Name on driver's license");
  });

  it('iata test1', async function () {
    const pdSchema: InternalPresentationDefinitionV2 = getFileAsJson('./test/dif_pe_examples/pdV2/pd-multi-sd-jwt-vp.json').presentation_definition;
    const vcs: string[] = [];
    vcs.push(getFile('test/dif_pe_examples/vc/vc-iata-order-sd.jwt').replace(/(\r\n|\n|\r)/gm, ''));
    vcs.push(getFile('test/dif_pe_examples/vc/vc-iata-epassport-sd.jwt').replace(/(\r\n|\n|\r)/gm, ''));
    const pd = SSITypesBuilder.modelEntityInternalPresentationDefinitionV2(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(vcs, hasher);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: ['FAsYneKJhWBP2n5E21ZzdY'],
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.areRequiredCredentialsPresent).toBe(Status.INFO);

    pex.evaluateCredentials(pd, result.verifiableCredential!);
    const presentationResult = pex.presentationFrom(pd, result.verifiableCredential!);
    expect(presentationResult).toBeDefined();
    const cred = await SDJwt.fromEncode(presentationResult.presentations[1].compactSdJwtVc, hasher);
    const claims = await cred.getClaims<Record<string, ClaimValue>>(hasher);

    // Check data group 1
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.birthdate).toBe('2024-10-09');
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.issuerCode).toBe('d');
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.sexCode).toBe('dd');
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.expiryDate).toBe('2024-10-10');
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.holdersName).toBe('dd');
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.natlCode).toBe('d');
    expect((claims.electronicPassport as { dataGroup1: Record<string, string> }).dataGroup1.passportNumberIdentifier).toBe('d');

    // Check empty objects
    expect((claims.electronicPassport as Record<string, Record<string, unknown>>).dataGroup2EncodedFaceBiometrics).toEqual({});
    expect((claims.electronicPassport as Record<string, Record<string, unknown>>).docSecurityObject).toEqual({});
    expect((claims.electronicPassport as Record<string, Record<string, unknown>>).dataGroup15.activeAuthentication).toEqual({});
    expect((claims.electronicPassport as Record<string, Record<string, unknown>>).digitalTravelCredential).toEqual({});

    // Top level claims
    expect(claims.vct).toBe('epassport_copy_vc');
    expect(claims.type).toBe('epassport_copy_vc');
    expect(claims.iss).toBe('did:web:agent.nb.dev.sphereon.com');
  });

  it('Funke test', async function () {
    const pdSchema: InternalPresentationDefinitionV2 = getFileAsJson('./test/dif_pe_examples/pdV2/pd-sd-jwt-vp-funke.json').presentation_definition;
    const vcs: string[] = [];
    vcs.push(getFile('test/dif_pe_examples/vc/vc-funke-pid-sd.jwt').replace(/(\r\n|\n|\r)/gm, ''));
    const pd = SSITypesBuilder.modelEntityInternalPresentationDefinitionV2(pdSchema);
    const evaluationClientWrapper: EvaluationClientWrapper = new EvaluationClientWrapper();
    const wvcs: WrappedVerifiableCredential[] = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(vcs, hasher);
    const result = evaluationClientWrapper.selectFrom(pd, wvcs, {
      holderDIDs: ['FAsYneKJhWBP2n5E21ZzdY'],
      limitDisclosureSignatureSuites: LIMIT_DISCLOSURE_SIGNATURE_SUITES,
    });
    expect(result.areRequiredCredentialsPresent).toBe(Status.INFO);

    pex.evaluateCredentials(pd, result.verifiableCredential!);
    const presentationResult = pex.presentationFrom(pd, result.verifiableCredential!);
    expect(presentationResult).toBeDefined();
    const cred = await SDJwt.fromEncode(presentationResult.presentations[0].compactSdJwtVc, hasher);
    const claims = await cred.getClaims<Record<string, ClaimValue>>(hasher);

    // Check personal information
    expect(claims.family_name).toBe('MUSTERMANN');
    expect(claims.given_name).toBe('ERIKA');

    // Check place of birth
    expect((claims.place_of_birth as { locality: string }).locality).toBe('BERLIN');

    // Check address details
    expect(
      (
        claims.address as {
          locality: string;
          postal_code: string;
          country: string;
          street_address: string;
        }
      ).locality,
    ).toBe('KÖLN');

    // Check issuing country
    expect(claims.issuing_country).toBe('DE');

    // Check age verification
    expect((claims.age_equal_or_over as { '18': boolean })['18']).toBe(true);
  });
});
