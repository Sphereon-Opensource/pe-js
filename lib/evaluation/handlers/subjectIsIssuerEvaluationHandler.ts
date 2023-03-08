import { ConstraintsV1, ConstraintsV2, Optionality } from '@sphereon/pex-models';
import { ICredential, WrappedVerifiableCredential } from '@sphereon/ssi-types';
import { PathComponent } from 'jsonpath';

import { Status } from '../../ConstraintUtils';
import { IInternalPresentationDefinition, InternalPresentationDefinitionV2 } from '../../types';
import PexMessages from '../../types/Messages';
import { getIssuerString, getSubjectIdsAsString, JsonPathUtils } from '../../utils';
import { HandlerCheckResult } from '../core';
import { EvaluationClient } from '../evaluationClient';

import { AbstractEvaluationHandler } from './abstractEvaluationHandler';

export class SubjectIsIssuerEvaluationHandler extends AbstractEvaluationHandler {
  constructor(client: EvaluationClient) {
    super(client);
  }

  public getName(): string {
    return 'SubjectIsIssuerEvaluation';
  }

  public handle(pd: IInternalPresentationDefinition, wrappedVcs: WrappedVerifiableCredential[]): void {
    // PresentationDefinitionV2 is the common denominator
    (pd as InternalPresentationDefinitionV2).input_descriptors.forEach((inputDescriptor, index) => {
      const constraints: ConstraintsV1 | ConstraintsV2 | undefined = inputDescriptor.constraints;
      if (constraints?.subject_is_issuer === Optionality.Required) {
        this.checkSubjectIsIssuer(inputDescriptor.id, wrappedVcs, index);
      } else {
        this.getResults().push(...wrappedVcs.map((_, vcIndex) => this.generateSuccessResult(index, `$[${vcIndex}]`, 'not applicable')));
      }
    });
    this.updatePresentationSubmission(pd);
  }

  private checkSubjectIsIssuer(inputDescriptorId: string, wrappedVcs: WrappedVerifiableCredential[], idIdx: number): void {
    this.client.presentationSubmission.descriptor_map.forEach((currentDescriptor) => {
      if (currentDescriptor.id === inputDescriptorId) {
        const vc: { path: PathComponent[]; value: ICredential }[] = JsonPathUtils.extractInputField(
          wrappedVcs.map((wvc) => wvc.credential),
          [currentDescriptor.path]
        ) as { path: PathComponent[]; value: ICredential }[];
        //TODO: ESSIFI-186
        if (vc[0] && vc[0].value && getSubjectIdsAsString(vc[0].value).indexOf(getIssuerString(vc[0].value)) !== -1) {
          this.getResults().push(this.generateSuccessResult(idIdx, currentDescriptor.path));
        } else {
          this.getResults().push(this.generateErrorResult(idIdx, currentDescriptor.path));
        }
      }
    });
  }

  private generateErrorResult(idIdx: number, vcPath: string): HandlerCheckResult {
    return {
      input_descriptor_path: `$.input_descriptors[${idIdx}]`,
      evaluator: this.getName(),
      status: Status.ERROR,
      message: PexMessages.SUBJECT_IS_NOT_ISSUER,
      verifiable_credential_path: vcPath,
    };
  }

  private generateSuccessResult(idIdx: number, vcPath: string, message?: string): HandlerCheckResult {
    return {
      input_descriptor_path: `$.input_descriptors[${idIdx}]`,
      evaluator: this.getName(),
      status: Status.INFO,
      message: message ?? PexMessages.SUBJECT_IS_ISSUER,
      verifiable_credential_path: vcPath,
    };
  }
}
