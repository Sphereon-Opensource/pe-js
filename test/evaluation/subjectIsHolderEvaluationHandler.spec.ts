import { PresentationSubmission } from '@sphereon/pex-models';
import { IVerifiablePresentation } from '@sphereon/ssi-types';

import { EvaluationClient } from '../../lib/evaluation';
import { SubjectIsHolderEvaluationHandler } from '../../lib/evaluation/handlers';
import { InternalPresentationDefinitionV1, SSITypesBuilder } from '../../lib/types';
import { getFileAsEntity, getFileAsJson } from '../utils/files';

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21';

describe('SubjectIsHolderEvaluationHandler tests', () => {
  it(`input descriptor's constraints.is_holder is present`, () => {
    const presentationDefinition = getFileAsEntity<InternalPresentationDefinitionV1>('./test/resources/pd_require_is_holder.json');
    const results = getFileAsJson('./test/resources/isHolderEvaluationResults.json');
    const evaluationClient: EvaluationClient = new EvaluationClient();
    const evaluationHandler: SubjectIsHolderEvaluationHandler = new SubjectIsHolderEvaluationHandler(evaluationClient);
    const presentation: IVerifiablePresentation = getFileAsEntity('./test/dif_pe_examples/vp/vp_subject_is_holder.json') as IVerifiablePresentation;
    evaluationClient.presentationSubmission = presentation.presentation_submission as PresentationSubmission;
    evaluationClient.wrappedVcs = SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!);
    evaluationClient.dids = [HOLDER_DID];
    evaluationHandler.handle(
      presentationDefinition,
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(presentation.verifiableCredential!),
    );
    expect(evaluationHandler.client.results).toEqual(results);
  });
});
