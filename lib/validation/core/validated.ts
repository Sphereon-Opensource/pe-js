import { NonEmptyArray, Checked } from '../../ConstraintUtils';

export type Validated = NonEmptyArray<Checked> | Checked;
