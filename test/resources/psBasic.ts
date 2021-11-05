import {PresentationDefinition} from "@sphereon/pe-models";

export class PsBasic {

  public getPresentationDefinition(): PresentationDefinition {
    return {
      id: "a30e3b91-fb77-4d22-95fa-871689c322e2",
      definition_id: "32f54163-7166-48f1-93d8-ff217bdb0653",
      descriptor_map: [
        {
          id: "banking_input_2",
          format: "jwt_vp",
          path: "$.outerClaim[0]",
          path_nested: {
            id: "banking_input_2",
            format: "ldp_vc",
            path: "$.innerClaim[1]",
            path_nested: {
              id: "banking_input_2",
              format: "jwt_vc",
              path: "$.mostInnerClaim[2]"
            }
          }
        }
      ]
    };
  }
}
