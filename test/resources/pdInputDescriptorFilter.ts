import {PresentationDefinition} from "@sphereon/pe-models";

export class PdInputDescriptorFilter {

  public getPresentationDefinition(): PresentationDefinition {
    return {
      id: "32f54163-7166-48f1-93d8-ff217bdb0653",
      input_descriptors: [
        {
          id: "banking_input_1",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
            }
          ]
        },
        {
          id: "banking_input_2",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
            }
          ],
          constraints: {}
        },
        {
          id: "banking_input_3",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
            }
          ],
          constraints: {
            fields: []
          }
        },
        {
          id: "banking_input_4",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
            }
          ],
          constraints: {
            fields: [
              {
                path: [
                  "$.test",
                  "$.vc.test",
                  "$.another_test"
                ],
                purpose: "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                filter: {
                  type: "string",
                  pattern: "did:example:123|did:example:456"
                }
              }
            ]
          }
        },
        {
          id: "banking_input_5",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
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
                purpose: "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                filter: {
                  type: "string",
                  pattern: "did:test:123|did:test:456"
                }
              }
            ]
          }
        },
        {
          id: "banking_input_6",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
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
                purpose: "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                filter: {
                  type: "string",
                  pattern: "did:example:123|did:foo:123"
                }
              }
            ]
          }
        },
        {
          id: "banking_input_7",
          name: "Bank Account Information",
          purpose: "We can only remit payment to a currently-valid bank account.",
          group: [
            "A"
          ],
          schema: [
            {
              uri: "https://bank-schemas.org/1.0.0/accounts.json"
            },
            {
              uri: "https://bank-schemas.org/2.0.0/accounts.json"
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
                purpose: "We can only verify bank accounts if they are attested by a trusted bank, auditor or regulatory authority.",
                filter: {
                  type: "string",
                  pattern: "did:example:123|did:example:456"
                }
              },
              {
                path: [
                  "$.credentialSubject.accounts[*].id",
                  "$.vc.credentialSubject.accounts[*].id",
                  "$.account[*].id"
                ],
                purpose: "We can only remit payment to a currently-valid bank account in the US, France, or Germany, submitted as an ABA Acct # or IBAN.",
                filter: {
                  type: "string",
                  pattern: "^[0-9]{10,12}|^(DE|FR)[0-9]{2}\\s?([0-9a-zA-Z]{4}\\s?){4}[0-9a-zA-Z]{2}$"
                }
              },
              {
                path: [
                  "$.credentialSubject.accounts[*].route",
                  "$.vc.credentialSubject.accounts[*].route",
                  "$.accounts[*].route"
                ],
                purpose: "We can only remit payment to a currently-valid account at a US, Japanese, or German federally-accredited bank, submitted as an ABA RTN or SWIFT code.",
                filter: {
                  type: "string",
                  pattern: "^[0-9]{9}|^([a-zA-Z]){4}([a-zA-Z]){2}([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})?$"
                }
              }
            ]
          }
        }
      ]
    };
  }
}
