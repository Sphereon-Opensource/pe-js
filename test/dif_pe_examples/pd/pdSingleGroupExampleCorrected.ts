import {PresentationDefinition} from "@sphereon/pe-models";

export class PdSingleGroupExampleCorrected {

  public getPresentationDefinition(): PresentationDefinition {
    return {
      id: "32f54163-7166-48f1-93d8-ff217bdb0653",
      submission_requirements: [
        {
          name: "Citizenship Information",
          rule: "pick",
          count: 1,
          from: "A"
        }
      ],
      input_descriptors: [
        {
          id: "citizenship_input_1",
          name: "EU Driver's License",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://eu.com/claims/DriversLicense.json"
            }
          ],
          constraints: {
            fields: [
              {
                path: [
                  "$.issuer",
                  "$.vc.issuer",
                  "$.iss"
                ],
                purpose: "We can only accept digital driver's licenses issued by national authorities of member states or trusted notarial auditors.",
                filter: {
                  type: "string",
                  pattern: "did:example:gov1|did:example:gov2"
                }
              },
              {
                path: [
                  "$.credentialSubject.dob",
                  "$.vc.credentialSubject.dob",
                  "$.dob"
                ],
                filter: {
                  type: "string",
                  format: "date",
                  formatMaximum: "1999-06-15"
                }
              }
            ]
          }
        },
        {
          id: "citizenship_input_2",
          name: "US Passport",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "did:foo:123/Collections/schema.us.gov/passport.json"
            }
          ],
          constraints: {
            fields: [
              {
                path: [
                  "$.credentialSubject.birth_date",
                  "$.vc.credentialSubject.birth_date",
                  "$.birth_date"
                ],
                filter: {
                  type: "string",
                  format: "date",
                  formatMaximum: "1999-05-16"
                }
              }
            ]
          }
        }
      ]
    };
  }
}
