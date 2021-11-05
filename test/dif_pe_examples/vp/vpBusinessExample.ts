import {VerifiablePresentation} from "../../../lib";

export class VpBusinessExample {

  public getVerifiablePresentation(): VerifiablePresentation {
    return {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/presentation-exchange/submission/v1"
      ],
      type: [
        "VerifiablePresentation",
        "PresentationSubmission"
      ],
      presentation_submission: {
        id: "a30e3b91-fb77-4d22-95fa-871689c322e2",
        definition_id: "32f54163-7166-48f1-93d8-ff217bdb0653",
        descriptor_map: [
          {
            id: "banking_input_2",
            format: "jwt_vc",
            path: "$.verifiableCredential[0]"
          },
          {
            id: "employment_input",
            format: "ldp_vc",
            path: "$.verifiableCredential[1]"
          },
          {
            id: "citizenship_input_1",
            format: "ldp_vc",
            path: "$.verifiableCredential[2]"
          }
        ]
      },
      verifiableCredential: [
        {
          comment: "IN REALWORLD VPs, THIS WILL BE A BIG UGLY OBJECT INSTEAD OF THE DECODED JWT PAYLOAD THAT FOLLOWS",

          "@context": [
            "https://licenses.example.com/business-license.json"
          ],
          id: "https://example.com/claims/BusinessLicense",
          type: [
            "EUDriversLicense"
          ],
          issuer: "did:example:123",
          issuanceDate: "2010-01-01T19:73:24Z",
          credentialSubject: {
            id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
            accounts: [
              {
                id: "1234567890",
                route: "DE-9876543210"
              },
              {
                id: "2457913570",
                route: "DE-0753197542"
              }
            ]
          },
          proof: {
            type: "Ed25519Signature2020",
            created: "2021-09-21T19:18:08Z",
            verificationMethod: "did:key:2021110414",
            proofPurpose: "assertionMethod",
            proofValue: "proofValue2021110415",
          }
        },
        {
          "@context": [
            "https://licenses.example.com/business-license.json"
          ],
          id: "https://business.example.org/schemas/business-license-history.json",
          type: [
            "VerifiableCredential",
            "GenericEmploymentCredential"
          ],
          issuer: "did:foo:123",
          issuanceDate: "2010-01-01T19:73:24Z",
          credentialSubject: {
            id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
            active: true
          },
          proof: {
            type: "EcdsaSecp256k1VerificationKey2019",
            created: "2017-06-18T21:19:10Z",
            proofPurpose: "assertionMethod",
            verificationMethod: "https://example.edu/issuers/keys/1",
          }
        },
        {
          "@context": [
            "https://licenses.example.com/business-license.json"
          ],
          id: "https://eu.com/claims/DriversLicense",
          type: [
            "EUDriversLicense"
          ],
          issuer: "did:foo:123",
          issuanceDate: "2010-01-01T19:73:24Z",
          credentialSubject: {
            id: "did:example:ebfeb1f712ebc6f1c276e12ec21",
            license: {
              number: "34DGE352",
              dob: "07/13/80"
            }
          },
          proof: {
            type: "RsaSignature2018",
            created: "2017-06-18T21:19:10Z",
            proofPurpose: "assertionMethod",
            verificationMethod: "https://example.edu/issuers/keys/1",
          }
        }
      ],
      holder: "holder2021110419",
      proof: {
        type: "RsaSignature2018",
        created: "2018-09-14T21:19:10Z",
        proofPurpose: "authentication",
        verificationMethod: "did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1",
        challenge: "1f44d55f-f161-4938-a659-f8026467f126",
        domain: "4jt78h47fh47",
      }
    };
  }
}
