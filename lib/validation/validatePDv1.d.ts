import type { ValidateFunction, ValidationError } from './validators';

declare module './validatePDv1.js' {
  const validate: ValidateFunction & { errors?: ValidationError[] | null };
  export default validate;
}
