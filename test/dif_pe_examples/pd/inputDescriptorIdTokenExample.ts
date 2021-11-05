import {PresentationDefinition} from "@sphereon/pe-models";

export class InputDescriptorIdTokenExample {

  public getPresentationDefinition(): PresentationDefinition {
    return {
      id: "32f54163-7166-48f1-93d8-ff217bdb0653",
      input_descriptors: [
        {
          id: "employment_input_xyz_gov",
          group: [
            "B"
          ],
          schema: [
            {
              uri: "https://login.idp.com/xyz.gov/.well-known/openid-configuration",
              required: true
            }
          ],
          name: "Verify XYZ Government Employment",
          purpose: "Verifying current employment at XYZ Government agency as proxy for permission to access this resource",
          constraints: {
            fields: [
              {
                path: [
                  "$.status"
                ],
                filter: {
                  type: "string",
                  pattern: "active"
                }
              }
            ]
          }
        }
      ]
    };
  }
}
