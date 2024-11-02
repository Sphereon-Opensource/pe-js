import fs from 'fs';

import { PresentationDefinitionV1, PresentationDefinitionV2 } from '@sphereon/pex-models';
import { IVerifiableCredential, IVerifiablePresentation } from '@sphereon/ssi-types';

import { InternalPresentationDefinitionV1 } from '../../lib/types';

export const getFile = (path: string): string => fs.readFileSync(path, 'utf-8');

export const getFileAsJson = (path: string) => JSON.parse(getFile(path));

export const getFileAsEntity = <
  T extends InternalPresentationDefinitionV1 | PresentationDefinitionV1 | PresentationDefinitionV2 | IVerifiablePresentation | IVerifiableCredential,
>(
  path: string,
): T => {
  const file = getFileAsJson(path);
  if ('presentation_definition' in file) {
    return file.presentation_definition as T;
  }
  return file as T;
};
