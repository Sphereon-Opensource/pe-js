import { Rules } from '@sphereon/pex-models';

import { SubmissionRequirementMatch } from '../../../lib';
import { SubmissionRequirementMatchType } from '../../../lib/evaluation/core';

describe('submissionRequirementMatch', () => {
  it('should return ok constructor works correctly', function () {
    const submissionRequirementMatch: SubmissionRequirementMatch = {
      name: 'test srm',
      areRequiredCredentialsPresent: 'info',
      from: 'A',
      id: 0,
      rule: {
        count: 2,
        type: 'all',
      },
      input_descriptors: [
        {
          areRequiredCredentialsPresent: 'info',
          id: '0c940f06-3d61-47dd-ae3e-db40509d8118',
          vc_path: ['$.verifiableCredential[1]'],
          type: SubmissionRequirementMatchType.InputDescriptor,
        },
      ],
      type: SubmissionRequirementMatchType.SubmissionRequirement,
    };
    expect(submissionRequirementMatch.from).toContain('A');
    expect(submissionRequirementMatch.rule.type).toBe(Rules.All);
    expect(submissionRequirementMatch.input_descriptors[0].vc_path[0]).toBe('$.verifiableCredential[1]');
  });
});
