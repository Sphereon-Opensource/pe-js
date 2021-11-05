import {VerifiablePresentation} from "../../../lib";

export class VpOpenIdConnectExample {

  public getVerifiablePresentation(): VerifiablePresentation {
    return {
      iss: "https://self-issued.me",
      sub: "248289761001",
      preferred_username: "superman445",
      presentation_submission: {
        id: "a30e3b91-fb77-4d22-95fa-871689c322e2",
        definition_id: "32f54163-7166-48f1-93d8-ff217bdb0653",
        descriptor_map: [
          {
            id: "banking_input_2",
            format: "jwt",
            path: "$._claim_sources.banking_input_2.JWT"
          },
          {
            id: "employment_input",
            format: "jwt_vc",
            path: "$._claim_sources.employment_input.VC_JWT"
          },
          {
            id: "citizenship_input_1",
            format: "ldp_vc",
            path: "$._claim_sources.citizenship_input_1.VC"
          }
        ]
      },
      _claim_names: {
        verified_claims: [
          "banking_input_2",
          "employment_input",
          "citizenship_input_1"
        ]
      },
      _claim_sources: {
        banking_input_2: {
          JWT: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5vdGhlcm9wLmNvbSIsInN1YiI6ImU4MTQ4NjAzLTg5MzQtNDI0NS04MjViLWMxMDhiOGI2Yjk0NSIsInZlcmlmaWVkX2NsYWltcyI6eyJ2ZXJpZmljYXRpb24iOnsidHJ1c3RfZnJhbWV3b3JrIjoiaWFsX2V4YW1wbGVfZ29sZCJ9LCJjbGFpbXMiOnsiZ2l2ZW5fbmFtZSI6Ik1heCIsImZhbWlseV9uYW1lIjoiTWVpZXIiLCJiaXJ0aGRhdGUiOiIxOTU2LTAxLTI4In19fQ.FArlPUtUVn95HCExePlWJQ6ctVfVpQyeSbe3xkH9MH1QJjnk5GVbBW0qe1b7R3lE-8iVv__0mhRTUI5lcFhLjoGjDS8zgWSarVsEEjwBK7WD3r9cEw6ZAhfEkhHL9eqAaED2rhhDbHD5dZWXkJCuXIcn65g6rryiBanxlXK0ZmcK4fD9HV9MFduk0LRG_p4yocMaFvVkqawat5NV9QQ3ij7UBr3G7A4FojcKEkoJKScdGoozir8m5XD83Sn45_79nCcgWSnCX2QTukL8NywIItu_K48cjHiAGXXSzydDm_ccGCe0sY-Ai2-iFFuQo2PtfuK2SqPPmAZJxEFrFoLY4g"
        },
        employment_input: {
          VC: {
            "@context": "https://www.w3.org/2018/credentials/v1",
            id: "https://business-standards.org/schemas/employment-history.json",
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
          }
        },
        citizenship_input_1: {
          VC: {
            "@context": "https://www.w3.org/2018/credentials/v1",
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
              type: "EcdsaSecp256k1VerificationKey2019",
              created: "2017-06-18T21:19:10Z",
              proofPurpose: "assertionMethod",
              verificationMethod: "https://example.edu/issuers/keys/1",
            }
          }
        }
      }
    };
  }
}
