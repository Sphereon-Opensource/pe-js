import { PresentationDefinitionV1, PresentationSubmission } from '@sphereon/pex-models';
import {
  CompactJWT,
  IPresentation,
  IProof,
  IVerifiableCredential,
  IVerifiablePresentation,
  JwtDecodedVerifiableCredential,
  OriginalVerifiablePresentation,
  WrappedVerifiablePresentation,
} from '@sphereon/ssi-types';

import { Status } from './ConstraintUtils';
import { PEX } from './PEX';
import { EvaluationClientWrapper, EvaluationResults, SelectResults } from './evaluation';
import { PresentationSignCallBackParams, PresentationSignOptions } from './signing';
import { SSITypesBuilder } from './types';
import { PresentationDefinitionV1VB, Validated, ValidationEngine } from './validation';

/**
 * This is the main interfacing class for using this library for v1 of presentation exchange
 */
export class PEXv1 {
  private _evaluationClientWrapper: EvaluationClientWrapper;

  constructor() {
    this._evaluationClientWrapper = new EvaluationClientWrapper();
  }

  /***
   * The evaluatePresentationV1 compares what is expected from a presentation with a presentationDefinitionV1.
   *
   * @param presentationDefinition the definition of what is expected in the presentation.
   * @param presentation the presentation which has to be evaluated in comparison of the definition.
   * @param limitDisclosureSignatureSuites the credential signature suites that support limit disclosure
   *
   * @return the evaluation results specify what was expected and was fulfilled and also specifies which requirements described in the input descriptors
   * were not fulfilled by the presentation.
   */
  public evaluatePresentation(
    presentationDefinition: PresentationDefinitionV1,
    presentation: OriginalVerifiablePresentation,
    limitDisclosureSignatureSuites?: string[]
  ): EvaluationResults {
    const presentationCopy: OriginalVerifiablePresentation = JSON.parse(JSON.stringify(presentation));
    const wrappedPresentation: WrappedVerifiablePresentation =
      SSITypesBuilder.mapExternalVerifiablePresentationToWrappedVP(presentationCopy);
    this._evaluationClientWrapper = new EvaluationClientWrapper();

    const holderDIDs = wrappedPresentation.presentation.holder ? [wrappedPresentation.presentation.holder] : [];
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(presentationDefinition);
    const result = this._evaluationClientWrapper.evaluate(
      pd,
      wrappedPresentation.vcs,
      holderDIDs,
      limitDisclosureSignatureSuites
    );
    if (result.value && result.value.descriptor_map.length) {
      const selectFromClientWrapper = new EvaluationClientWrapper();
      const selectResults: SelectResults = selectFromClientWrapper.selectFrom(
        pd,
        wrappedPresentation.vcs,
        holderDIDs,
        limitDisclosureSignatureSuites
      );
      if (selectResults.areRequiredCredentialsPresent !== Status.ERROR) {
        result.errors = [];
      }
    }
    return result;
  }

  /***
   * To evaluate compares what is expected from a verifiableCredentials with the presentationDefinition.
   *
   * @param presentationDefinition the v1 definition of what is expected in the presentation.
   * @param verifiableCredentials the verifiable credentials which are candidates to fulfill requirements defined in the presentationDefinition param.
   * @param holderDIDs the list of the DIDs that the wallet holders controlls.
   * @param limitDisclosureSignatureSuites the credential signature suites that support limit disclosure
   *
   * @return the evaluation results specify what was expected and was fulfilled and also specifies which requirements described in the input descriptors
   * were not fulfilled by the verifiable credentials.
   */
  public evaluateCredentials(
    presentationDefinition: PresentationDefinitionV1,
    verifiableCredentials: (IVerifiableCredential | JwtDecodedVerifiableCredential | CompactJWT)[],
    holderDIDs?: string[],
    limitDisclosureSignatureSuites?: string[]
  ): EvaluationResults {
    this._evaluationClientWrapper = new EvaluationClientWrapper();
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(presentationDefinition);
    const wrappedVerifiableCredentials =
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(verifiableCredentials);

    const result = this._evaluationClientWrapper.evaluate(
      pd,
      wrappedVerifiableCredentials,
      holderDIDs,
      limitDisclosureSignatureSuites
    );
    if (result.value && result.value.descriptor_map.length) {
      const selectFromClientWrapper = new EvaluationClientWrapper();
      const selectResults: SelectResults = selectFromClientWrapper.selectFrom(
        pd,
        wrappedVerifiableCredentials,
        holderDIDs,
        limitDisclosureSignatureSuites
      );
      result.areRequiredCredentialsPresent = selectResults.areRequiredCredentialsPresent;
    } else {
      result.areRequiredCredentialsPresent = Status.ERROR;
    }
    return result;
  }

  /**
   * The selectFrom method is a helper function that helps filter out the verifiable credentials which can not be selected and returns
   * the selectable credentials.
   *
   * @param presentationDefinition the v1 definition of what is expected in the presentation.
   * @param verifiableCredentials verifiable credentials are the credentials from wallet provided to the library to find selectable credentials.
   * @param holderDIDs the decentralized identity of the wallet holder. This is used to identify the credentials issued to the holder of wallet.
   * @param limitDisclosureSignatureSuites the credential signature suites that support limit disclosure
   *
   * @return the selectable credentials.
   */
  public selectFrom(
    presentationDefinition: PresentationDefinitionV1,
    verifiableCredentials: (IVerifiableCredential | JwtDecodedVerifiableCredential | CompactJWT)[],
    holderDIDs?: string[],
    limitDisclosureSignatureSuites?: string[]
  ): SelectResults {
    const verifiableCredentialCopy = JSON.parse(JSON.stringify(verifiableCredentials));
    this._evaluationClientWrapper = new EvaluationClientWrapper();
    return this._evaluationClientWrapper.selectFrom(
      SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(presentationDefinition),
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(verifiableCredentialCopy),
      holderDIDs,
      limitDisclosureSignatureSuites
    );
  }

  /**
   * This method helps create a submittablePresentation. A submittablePresentation after signing becomes a Presentation. And can be sent to
   * the verifier after signing it.
   *
   * IMPORTANT NOTE: this method creates a presentation object based on the SELECTED verifiable credentials. You can get the selected verifiable credentials using selectFrom method
   *
   * @param presentationDefinition the v1 definition of what is expected in the presentation.
   * @param selectedCredential the credentials which were declared selectable by getSelectableCredentials and then chosen by the intelligent-user
   * (e.g. human).
   * @param holderDID optional; the decentralized identity of the wallet holder. This is used to identify the holder of the presentation.
   *
   * @return the presentation.
   */
  public presentationFrom(
    presentationDefinition: PresentationDefinitionV1,
    selectedCredential: (IVerifiableCredential | JwtDecodedVerifiableCredential | CompactJWT)[],
    holderDID?: string
  ): IPresentation {
    const presentationSubmission = this._evaluationClientWrapper.submissionFrom(
      SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(presentationDefinition),
      SSITypesBuilder.mapExternalVerifiableCredentialsToWrappedVcs(selectedCredential)
    );
    return PEX.getPresentation(presentationSubmission, selectedCredential, holderDID);
  }

  /**
   * This method validates whether an object is usable as a presentation definition or not.
   *
   * @param presentationDefinitionV1 the object to be validated.
   *
   * @return the validation results to reveal what is acceptable/unacceptable about the passed object to be considered a valid presentation definition
   */
  public validateDefinition(presentationDefinitionV1: PresentationDefinitionV1): Validated {
    const pd = SSITypesBuilder.createInternalPresentationDefinitionV1FromModelEntity(presentationDefinitionV1);
    return new ValidationEngine().validate([
      {
        bundler: new PresentationDefinitionV1VB('root'),
        target: pd,
      },
    ]);
  }

  /**
   * This method validates whether an object is usable as a presentation submission or not.
   *
   * @param presentationSubmission the object to be validated.
   *
   * @return the validation results to reveal what is acceptable/unacceptable about the passed object to be considered a valid presentation submission
   */
  public validateSubmission(presentationSubmission: PresentationSubmission): Validated {
    return new PEX().validateSubmission(presentationSubmission);
  }

  /**
   * This method can be used to combine a v1 definition, selected Verifiable Credentials, together with
   * signing options and a callback to sign a presentation, making it a Verifiable Presentation before sending. With an async callback
   *
   * Please note that PEX has no signature support on purpose. We didn't want this library to depend on all kinds of signature suites.
   * The callback function next to the Signing Params also gets a Presentation which is evaluated against the definition.
   * It is up to you to decide whether you simply update the supplied partial proof and add it to the presentation in the callback,
   * or whether you will use the selected Credentials, Presentation definition, evaluation results and/or presentation submission together with the signature options
   *
   * @param presentationDefinition the Presentation Definition V1
   * @param selectedCredentials the PEX and/or User selected/filtered credentials that will become part of the Verifiable Presentation
   * @param signingCallBack the function which will be provided as a parameter. And this will be the method that will be able to perform actual
   *        signing. One example of signing is available in the project named. pe-selective-disclosure.
   * @param options: Signing Params these are the signing params required to sign.
   *
   * @return the signed and thus Verifiable Presentation.
   */
  public async verifiablePresentationFromAsync(
    presentationDefinition: PresentationDefinitionV1,
    selectedCredentials: (IVerifiableCredential | JwtDecodedVerifiableCredential | CompactJWT)[],
    signingCallBack: (callBackParams: PresentationSignCallBackParams) => IVerifiablePresentation,
    options: PresentationSignOptions
  ): Promise<IVerifiablePresentation> {
    const { holder, signatureOptions, proofOptions } = options;

    function limitedDisclosureSuites() {
      let limitDisclosureSignatureSuites: string[] = [];
      if (proofOptions?.typeSupportsSelectiveDisclosure) {
        if (!proofOptions?.type) {
          throw Error('Please provide a proof type if you enable selective disclosure');
        }
        limitDisclosureSignatureSuites = [proofOptions.type];
      }
      return limitDisclosureSignatureSuites;
    }

    const holderDIDs: string[] = holder ? [holder] : [];
    const limitDisclosureSignatureSuites = limitedDisclosureSuites();
    this.evaluateCredentials(presentationDefinition, selectedCredentials, holderDIDs, limitDisclosureSignatureSuites);

    const presentation = this.presentationFrom(presentationDefinition, selectedCredentials, holder);
    const evaluationResults = this.evaluatePresentation(
      presentationDefinition,
      presentation as IVerifiablePresentation,
      limitDisclosureSignatureSuites
    );
    if (!evaluationResults.value) {
      throw new Error('Could not get evaluation results from presentation');
    }

    const proof: Partial<IProof> = {
      type: proofOptions?.type,
      verificationMethod: signatureOptions?.verificationMethod,
      created: proofOptions?.created ? proofOptions.created : new Date().toISOString(),
      proofPurpose: proofOptions?.proofPurpose,
      proofValue: signatureOptions?.proofValue,
      jws: signatureOptions?.jws,
      challenge: proofOptions?.challenge,
      nonce: proofOptions?.nonce,
      domain: proofOptions?.domain,
    };

    const callBackParams: PresentationSignCallBackParams = {
      options,
      presentation,
      presentationDefinition,
      selectedCredentials,
      proof,
      presentationSubmission: evaluationResults.value,
      evaluationResults,
    };

    return await signingCallBack(callBackParams);
  }

  /**
   * This method can be used to combine a v1 definition, selected Verifiable Credentials, together with
   * signing options and a callback to sign a presentation, making it a Verifiable Presentation before sending. With an async callback
   *
   * Please note that PEX has no signature support on purpose. We didn't want this library to depend on all kinds of signature suites.
   * The callback function next to the Signing Params also gets a Presentation which is evaluated against the definition.
   * It is up to you to decide whether you simply update the supplied partial proof and add it to the presentation in the callback,
   * or whether you will use the selected Credentials, Presentation definition, evaluation results and/or presentation submission together with the signature options
   *
   * @deprecated This method in current form will not be supported in our next release. This will be changed to an "async" function.
   *
   * @param presentationDefinition the Presentation Definition V1
   * @param selectedCredentials the PEX and/or User selected/filtered credentials that will become part of the Verifiable Presentation
   * @param signingCallBack the function which will be provided as a parameter. And this will be the method that will be able to perform actual
   *        signing. One example of signing is available in the project named. pe-selective-disclosure.
   * @param options: Signing Params these are the signing params required to sign.
   *
   * @return the signed and thus Verifiable Presentation.
   */
  public verifiablePresentationFrom(
    presentationDefinition: PresentationDefinitionV1,
    selectedCredentials: (IVerifiableCredential | JwtDecodedVerifiableCredential | CompactJWT)[],
    signingCallBack: (callBackParams: PresentationSignCallBackParams) => IVerifiablePresentation,
    options: PresentationSignOptions
  ): IVerifiablePresentation {
    const { holder, signatureOptions, proofOptions } = options;

    function limitedDisclosureSuites() {
      let limitDisclosureSignatureSuites: string[] = [];
      if (proofOptions?.typeSupportsSelectiveDisclosure) {
        if (!proofOptions?.type) {
          throw Error('Please provide a proof type if you enable selective disclosure');
        }
        limitDisclosureSignatureSuites = [proofOptions.type];
      }
      return limitDisclosureSignatureSuites;
    }

    const holderDIDs: string[] = holder ? [holder] : [];
    const limitDisclosureSignatureSuites = limitedDisclosureSuites();
    this.evaluateCredentials(presentationDefinition, selectedCredentials, holderDIDs, limitDisclosureSignatureSuites);

    const presentation = this.presentationFrom(presentationDefinition, selectedCredentials, holder);
    const evaluationResults = this.evaluatePresentation(
      presentationDefinition,
      presentation as IVerifiablePresentation,
      limitDisclosureSignatureSuites
    );
    if (!evaluationResults.value) {
      throw new Error('Could not get evaluation results from presentation');
    }

    const proof: Partial<IProof> = {
      type: proofOptions?.type,
      verificationMethod: signatureOptions?.verificationMethod,
      created: proofOptions?.created ? proofOptions.created : new Date().toISOString(),
      proofPurpose: proofOptions?.proofPurpose,
      proofValue: signatureOptions?.proofValue,
      jws: signatureOptions?.jws,
      challenge: proofOptions?.challenge,
      nonce: proofOptions?.nonce,
      domain: proofOptions?.domain,
    };

    const callBackParams: PresentationSignCallBackParams = {
      options,
      presentation,
      presentationDefinition,
      selectedCredentials,
      proof,
      presentationSubmission: evaluationResults.value,
      evaluationResults,
    };

    return signingCallBack(callBackParams);
  }
}
