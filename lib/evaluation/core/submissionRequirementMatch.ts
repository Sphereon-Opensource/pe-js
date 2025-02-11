import { Status } from '../../ConstraintUtils';

export enum SubmissionRequirementMatchType {
  /**
   * Match for a submission_requirements entry in the presentation definition. If the match type
   * is `SubmissionRequirement` the {@link SubmissionRequirementMatch.id} property refers to the index
   * of the `submission_requirements` entry in the presentation definition.
   *
   * If the match is a nested match result, this match type refers to the nested index. E.g. a presentation
   * definition has three `submission_requirements` entries where the second submission requirement (index 1)
   * has two `from_nested` `submission_requirements` entries and this match refers to the second (index 1) of
   * this from nested, the {@link SubmissionRequirementMatch.id} property of the outer match refers to the outer index
   * in the `submission_requirements` entries, and the nested {@link SubmissionRequirementMatch.id} refers to index of the
   * `from_nested` entries. This can go multiple layers deep.
   */
  SubmissionRequirement = 'SubmissionRequirement',

  /**
   * Match for an input_descriptors entry in the presentation definition. This type will be used
   * if no submission_requirements are present in the presentation definition. If the match type
   * is `InputDescriptor` the {@link SubmissionRequirementMatch.id} property refers to the `id`
   * of the `input_descriptors` entry in the presentation definition.
   *
   * You need to select exactly ONE of the vcs from vc_path in this case for the submission
   */
  InputDescriptor = 'InputDescriptor',
}

export interface SubmissionRequirementMatchFromNested extends SubmissionRequirementMatchFromBase {
  from_nested: Array<SubmissionRequirementMatchFromNested | SubmissionRequirementMatchFrom>;

  // Helps with type narrowing
  from?: never;
}

export interface SubmissionRequirementMatchFrom extends SubmissionRequirementMatchFromBase {
  from: string;

  input_descriptors: SubmissionRequirementMatchInputDescriptor[];

  // Helps with type narrowing
  from_nested?: never;
}

export interface SubmissionRequirementMatchFromBase {
  areRequiredCredentialsPresent: Status;
  type: SubmissionRequirementMatchType.SubmissionRequirement;
  id: number;
  name?: string;

  rule:
    | {
        type: 'pick';
        count?: number;
        min?: number;
        max?: number;
      }
    | {
        type: 'all';
        count: number;
      };
}

export interface SubmissionRequirementMatchInputDescriptor {
  areRequiredCredentialsPresent: Status;
  id: string;
  name?: string;
  type: SubmissionRequirementMatchType.InputDescriptor;
  vc_path: string[];
}

export type SubmissionRequirementMatch =
  | SubmissionRequirementMatchFrom
  | SubmissionRequirementMatchFromNested
  | SubmissionRequirementMatchInputDescriptor;
