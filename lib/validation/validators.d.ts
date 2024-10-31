import { PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models';

export interface ValidateFunction {
  (data: unknown): boolean;

  errors?: ValidationError[];
}

export type ValidationParentSchema = {
  type?: string | string[];
  properties?: {
    [key: string]: {
      type?: string;
      enum?: string[];
      items?: {
        type?: string;
        $ref?: string;
      };
      properties?: Record<string, unknown>;
      required?: string[];
      additionalProperties?: boolean;
      $ref?: string;
    };
  };
  required?: string[];
  additionalProperties?: boolean;
  items?: {
    type?: string;
    $ref?: string;
  };
};

export type ValidationError = {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  params: {
    type?: string | string[];
    limit?: number;
    comparison?: string;
    missingProperty?: string;
    additionalProperty?: string;
    propertyName?: string;
    i?: number;
    j?: number;
    allowedValues?: string[] | readonly string[];
    passingSchemas?: number | number[];
  };
  message: string;
  schema: boolean | ValidationParentSchema;
  parentSchema: ValidationParentSchema;
  data: PresentationDefinitionV1 | PresentationDefinitionV2;
};
