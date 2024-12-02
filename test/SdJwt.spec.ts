import { createHash } from 'crypto';

import { PresentationDefinitionV2 } from '@sphereon/pex-models';
import { SdJwtDecodedVerifiableCredential } from '@sphereon/ssi-types';

import { PEX, PresentationSubmissionLocation, Status, Validated } from '../lib';
import { SubmissionRequirementMatchType } from '../lib/evaluation/core';
import { calculateSdHash } from '../lib/utils';

export const hasher = (data: string) => createHash('sha256').update(data).digest();

const decodedSdJwtVc = {
  compactSdJwtVc:
    'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYXQiOjE3MDA0NjQ3MzYwNzYsImlzcyI6ImRpZDprZXk6c29tZS1yYW5kb20tZGlkLWtleSIsIm5iZiI6MTcwMDQ2NDczNjE3NiwidmN0IjoiaHR0cHM6Ly9oaWdoLWFzc3VyYW5jZS5jb20vU3RhdGVCdXNpbmVzc0xpY2Vuc2UiLCJ1c2VyIjp7Il9zZCI6WyI5QmhOVDVsSG5QVmpqQUp3TnR0NDIzM216MFVVMUd3RmFmLWVNWkFQV0JNIiwiSVl5d1FQZl8tNE9hY2Z2S2l1cjRlSnFMa1ZleWRxcnQ1Y2UwMGJReWNNZyIsIlNoZWM2TUNLakIxeHlCVl91QUtvLURlS3ZvQllYbUdBd2VGTWFsd05xbUEiLCJXTXpiR3BZYmhZMkdoNU9pWTRHc2hRU1dQREtSeGVPZndaNEhaQW5YS1RZIiwiajZ6ZFg1OUJYZHlTNFFaTGJITWJ0MzJpenRzWXdkZzRjNkpzWUxNc3ZaMCIsInhKR3Radm41cFM4VEhqVFlJZ3MwS1N5VC1uR3BSR3hDVnp6c1ZEbmMyWkUiXX0sImxpY2Vuc2UiOnsibnVtYmVyIjoxMH0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwieSI6Ilp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIl90YnpMeHBaeDBQVHVzV2hPOHRUZlVYU2ZzQjVlLUtrbzl3dmZaaFJrYVkiLCJ1WmNQaHdUTmN4LXpNQU1zemlYMkFfOXlJTGpQSEhobDhEd2pvVXJLVVdZIl19.HAcudVInhNpXkTPQGNosjKTFRJWgKj90NpfloRaDQchGd4zxc1ChWTCCPXzUXTBypASKrzgjZCiXlTr0bzmLAg~WyJHeDZHRUZvR2t6WUpWLVNRMWlDREdBIiwiZGF0ZU9mQmlydGgiLCIyMDAwMDEwMSJd~WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ~WyJNV1ZieGJqVFZxUXdLS3h2UGVZdWlnIiwibGFzdE5hbWUiLCJEb2UiXQ~',
  signedPayload: {
    iat: 1700464736076,
    iss: 'did:key:some-random-did-key',
    nbf: 1700464736176,
    vct: 'https://high-assurance.com/StateBusinessLicense',
    user: {
      _sd: [
        '9BhNT5lHnPVjjAJwNtt4233mz0UU1GwFaf-eMZAPWBM',
        'IYywQPf_-4OacfvKiur4eJqLkVeydqrt5ce00bQycMg',
        'Shec6MCKjB1xyBV_uAKo-DeKvoBYXmGAweFMalwNqmA',
        'WMzbGpYbhY2Gh5OiY4GshQSWPDKRxeOfwZ4HZAnXKTY',
        'j6zdX59BXdyS4QZLbHMbt32iztsYwdg4c6JsYLMsvZ0',
        'xJGtZvn5pS8THjTYIgs0KSyT-nGpRGxCVzzsVDnc2ZE',
      ],
    },
    license: {
      number: 10,
    },
    cnf: {
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
        y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
      },
    },
    _sd_alg: 'sha-256',
    _sd: ['_tbzLxpZx0PTusWhO8tTfUXSfsB5e-Kko9wvfZhRkaY', 'uZcPhwTNcx-zMAMsziX2A_9yILjPHHhl8DwjoUrKUWY'],
  },
  decodedPayload: {
    iat: 1700464736076,
    iss: 'did:key:some-random-did-key',
    nbf: 1700464736176,
    vct: 'https://high-assurance.com/StateBusinessLicense',
    user: {
      dateOfBirth: '20000101',
      name: 'John',
      lastName: 'Doe',
    },
    license: {
      number: 10,
    },
    cnf: {
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
        y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
      },
    },
  },
  disclosures: [
    {
      encoded: 'WyJHeDZHRUZvR2t6WUpWLVNRMWlDREdBIiwiZGF0ZU9mQmlydGgiLCIyMDAwMDEwMSJd',
      decoded: ['Gx6GEFoGkzYJV-SQ1iCDGA', 'dateOfBirth', '20000101'],
      digest: 'IYywQPf_-4OacfvKiur4eJqLkVeydqrt5ce00bQycMg',
    },
    {
      encoded: 'WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ',
      decoded: ['u-Kwrbo2F_LLPzGRdMW-KA', 'name', 'John'],
      digest: 'xJGtZvn5pS8THjTYIgs0KSyT-nGpRGxCVzzsVDnc2ZE',
    },
    {
      encoded: 'WyJNV1ZieGJqVFZxUXdLS3h2UGVZdWlnIiwibGFzdE5hbWUiLCJEb2UiXQ',
      decoded: ['MWVbxbjTVqQwKKxvPeYuig', 'lastName', 'Doe'],
      digest: 'j6zdX59BXdyS4QZLbHMbt32iztsYwdg4c6JsYLMsvZ0',
    },
  ],
} satisfies SdJwtDecodedVerifiableCredential;

const decodedSdJwtVcNewPid = {
  compactSdJwtVc:
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lVemR3V0d0S1RVaGpWR0l5ZG5CU2RIZzVhVzFFZURCNFUzSm5WSGRMWDFGWU1qUldOMGRUV1U5Tk1DSXNJbmtpT2lKM1VYWjJiM054YW1Ga1ltOTVhbWhzWDFCb1JtTnlkRGQzWlVsSU5EaDZaVTl2VFcxcWJpMHljbEJqSW4wIzAiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2ljVU50Y0dsNWFtOVlVblkxUm1WalgwRnhPR0Z5VUU5bVRrdEZSSFl5U0ZkSFUyRm1UVGR5TkVGSGJ5SXNJbmtpT2lKc1ZscERZVGhTZHpscFkyRnVhVTlYU2tVeWVHTmFVM1J1WVhKdVZYSklhek5qVmxwUFpubFFiVlE0SW4wIzAiLCJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lVemR3V0d0S1RVaGpWR0l5ZG5CU2RIZzVhVzFFZURCNFUzSm5WSGRMWDFGWU1qUldOMGRUV1U5Tk1DSXNJbmtpT2lKM1VYWjJiM054YW1Ga1ltOTVhbWhzWDFCb1JtTnlkRGQzWlVsSU5EaDZaVTl2VFcxcWJpMHljbEJqSW4wIzAiLCJpYXQiOjE3MzMxNTU0OTMsInZjdCI6Imh0dHBzOi8vZXhhbXBsZS5ibWkuYnVuZC5kZS9jcmVkZW50aWFsL3BpZC8xLjAiLCJfc2QiOlsiOEZDelV2VkhOVDA1WmdDRXptdnNRc0ZLekVVTVZWLW9QMUJDWVkwakxsMCIsIkVuYlRUbFJseUNRdXZ6NkhHZm0yZmtmT3Z2NDMzSE9CcE9ub3ViZzBVeVUiLCJRTEhJZnNvdXR6Xy1hdW96dmpnRUQ2ZUpQV1hVaWZiMkJENDJUQXpFaGlFIiwiZV9yTDlqQXBfRVJrb21OZl9PRGNjdFNBSVREZWNCUWFMRVJyRzVFcFRXQSIsIm00eTR5RVd1cjhRdkdMQ0ROQ3hVY0RwdDc4NDMxZDU0czVzeEUxUkpGRlEiLCJ1cG9Bc3B5Zm11RHhzX3RNXzdmZGFxZVJYMWhGc3FqcVlHSnFfZ3VjYW80Il0sIl9zZF9hbGciOiJTSEEtMjU2In0.PFI-nq8CildqIDp-oKYWaHAnpRK5bRGS4tM6aqnyvNtVZqEkjB3TpxJqtlcPDmynMXsf-ZKxdFkWBhkqMakLHw~WyI4NmYxYWYyOC05MWVkLTRkZDktYWE0Yy0xNTdmODYzNDU4Y2QiLCJnaXZlbl9uYW1lIiwiSm9obiJd~WyIxNDRiYjY5NS1hZGFhLTQyNDMtODY3NS1mOWY3YTA4YzczMjAiLCJmYW1pbHlfbmFtZSIsIkRvZSJd~WyJjNjg2NmU4Mi1kZGJlLTQ0YzMtYjliZS0zOThlOTNkMTA4Y2MiLCJlbWFpbCIsImpvaG5kZW9AZXhhbXBsZS5jb20iXQ~WyI4MTczMjkzNC03ZDMwLTQ4MzAtOWRjMi1hYjgxNjNkMjg4YzciLCJwaG9uZSIsIisxLTIwMi01NTUtMDEwMSJd~WyI5ODQ3OWU1Yi1iOGE0LTRiOTItOTA5Mi1kZjdhNTQ5NGZiMTMiLCJhZGRyZXNzIix7InN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsImNvdW50cnkiOiJVUyJ9XQ~WyI0NDQ1ZGYzNi1iN2E2LTQ3Y2QtODZiYS0wMjBmMzQzZDc2NDciLCJiaXJ0aGRhdGUiLCIxOTQwLTAxLTAxIl0~',
};

const decodedSdJwtVcOldPid = {
  compactSdJwtVc:
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lRbE5YUWtFdE5UZHVkeko1TldOMVZsZFdPRjgzUm5aSVozbEpTamQ0TVhCMWRsbzVkMmMyUWpKUlZTSXNJbmtpT2lKNFpUaGZkRXRLY1VKemJ6aHJNRmxDUkhaUFgwOXpkeTFKTVdGcWRVcFFiRU40U2twNGJIWmZRVVJCSW4wIzAiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lOMHBVYVRkWlREUXhhRTlXUm5oNWRtcEJjWE0wUVZnMmNsRnRPVzlFZDNoSmNsUkJhSFp2ZEV0WldTSXNJbmtpT2lJMWRrbDFPVzVmTm1JMk1FSjROMlJJU1VveldpMXNlRzh0VFhjelluVlpSV0ZhVjNWRE5XSjNiemRySW4wIzAiLCJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lRbE5YUWtFdE5UZHVkeko1TldOMVZsZFdPRjgzUm5aSVozbEpTamQ0TVhCMWRsbzVkMmMyUWpKUlZTSXNJbmtpT2lKNFpUaGZkRXRLY1VKemJ6aHJNRmxDUkhaUFgwOXpkeTFKTVdGcWRVcFFiRU40U2twNGJIWmZRVVJCSW4wIzAiLCJpYXQiOjE3MzMxNTgwODksInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsIl9zZCI6WyIwa0lWQzJOVHZ2eTFnek9QSEpOUk9oSjhmaHB3dEIwWEhBOUVXblFKblVZIiwiRU1UeURmR0xLSjkzV3o1dFp1X1JfckFtM0hnZG81VDBqM01HYmhoZDBjbyIsIkhQNVk4d0RsS0Q5VjhqWVFGZHI0MVh3dWlMLXhxaVZKUmY1ODZzV0tJMDQiLCJYWVFFYzlPZk0weFVyWWJodVl3c1VDWHhBLWtuMnozclc1eko1aVdwekMwIiwiZ2Jfem9TeE1aT2VqdElpZ3FCeTNtemhxUXhYT0FmaUMybFd2ZkdPSi1LbyIsInd2cFctMWRyNV91RVZjTG9Ec3RpRUZPYTRrYi11dVcyaFlmZzdETTNzSWciXSwiX3NkX2FsZyI6IlNIQS0yNTYifQ.pVRW95_MZ7hdgTeXMoL5FqvWRgezKI1cJ-QPfDiUNdeQxl6bS_Vh5jvm4vBgHPgG1srxtNuOKiQshGTM8CAwyg~WyJhM2Q2OWEwMi02N2Y3LTQ4MzUtOWRmZC0yMjUxN2IxZjRiMTIiLCJnaXZlbl9uYW1lIiwiSm9obiJd~WyIxYTFhNTg5Ni01M2EyLTQzY2QtODNhYy1jMGNmODhkZjZmNTEiLCJmYW1pbHlfbmFtZSIsIkRvZSJd~WyJmZDViMTFmNC04ZDllLTQzYmYtYTVkMC04ODE5YTJjYjg2MzEiLCJlbWFpbCIsImpvaG5kZW9AZXhhbXBsZS5jb20iXQ~WyJkY2IwNTJjYS02ZDFiLTQ3NDktODNmYi1lNjkxYzIyZTY2ZjAiLCJwaG9uZSIsIisxLTIwMi01NTUtMDEwMSJd~WyI1MDdjM2MyNi0yZjQxLTQwNWEtOTZkMS1lNTI1ZWM2Y2VjNTQiLCJhZGRyZXNzIix7InN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsImNvdW50cnkiOiJVUyJ9XQ~WyIwNzBlZjYyNy05NTAyLTRkMTYtYTNjYi1lNTAwZTViOTk0YWIiLCJiaXJ0aGRhdGUiLCIxOTQwLTAxLTAxIl0~',
};

// This is the expected output SD-JWT based on the presentation definition defined below
const decodedSdJwtVcWithDisclosuresRemoved = {
  // 3 disclosures not included
  compactSdJwtVc:
    'eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYXQiOjE3MDA0NjQ3MzYwNzYsImlzcyI6ImRpZDprZXk6c29tZS1yYW5kb20tZGlkLWtleSIsIm5iZiI6MTcwMDQ2NDczNjE3NiwidmN0IjoiaHR0cHM6Ly9oaWdoLWFzc3VyYW5jZS5jb20vU3RhdGVCdXNpbmVzc0xpY2Vuc2UiLCJ1c2VyIjp7Il9zZCI6WyI5QmhOVDVsSG5QVmpqQUp3TnR0NDIzM216MFVVMUd3RmFmLWVNWkFQV0JNIiwiSVl5d1FQZl8tNE9hY2Z2S2l1cjRlSnFMa1ZleWRxcnQ1Y2UwMGJReWNNZyIsIlNoZWM2TUNLakIxeHlCVl91QUtvLURlS3ZvQllYbUdBd2VGTWFsd05xbUEiLCJXTXpiR3BZYmhZMkdoNU9pWTRHc2hRU1dQREtSeGVPZndaNEhaQW5YS1RZIiwiajZ6ZFg1OUJYZHlTNFFaTGJITWJ0MzJpenRzWXdkZzRjNkpzWUxNc3ZaMCIsInhKR3Radm41cFM4VEhqVFlJZ3MwS1N5VC1uR3BSR3hDVnp6c1ZEbmMyWkUiXX0sImxpY2Vuc2UiOnsibnVtYmVyIjoxMH0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwieSI6Ilp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX0sIl9zZF9hbGciOiJzaGEtMjU2IiwiX3NkIjpbIl90YnpMeHBaeDBQVHVzV2hPOHRUZlVYU2ZzQjVlLUtrbzl3dmZaaFJrYVkiLCJ1WmNQaHdUTmN4LXpNQU1zemlYMkFfOXlJTGpQSEhobDhEd2pvVXJLVVdZIl19.HAcudVInhNpXkTPQGNosjKTFRJWgKj90NpfloRaDQchGd4zxc1ChWTCCPXzUXTBypASKrzgjZCiXlTr0bzmLAg~WyJ1LUt3cmJvMkZfTExQekdSZE1XLUtBIiwibmFtZSIsIkpvaG4iXQ~',
  decodedPayload: {
    iat: 1700464736076,
    iss: 'did:key:some-random-did-key',
    nbf: 1700464736176,
    vct: 'https://high-assurance.com/StateBusinessLicense',
    // Some fields from user not disclosed
    user: {
      name: 'John',
    },
    license: {
      number: 10,
    },
    cnf: {
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
        y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
      },
    },
  },
  // Only first disclosure included (user.name)
  disclosures: [decodedSdJwtVc.disclosures[1]],
  signedPayload: decodedSdJwtVc.signedPayload,
} satisfies SdJwtDecodedVerifiableCredential;

const pex = new PEX({
  hasher,
});

function getPresentationDefinitionV2(): PresentationDefinitionV2 {
  return {
    id: '32f54163-7166-48f1-93d8-ff217bdb0653',
    name: 'Conference Entry Requirements',
    purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
    format: {
      'vc+sd-jwt': {},
    },
    input_descriptors: [
      {
        id: 'wa_driver_license',
        name: 'Washington State Business License',
        purpose: 'We can only allow licensed Washington State business representatives into the WA Business Conference',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            {
              path: ['$.vct'],
              filter: {
                type: 'string',
                const: 'https://high-assurance.com/StateBusinessLicense',
              },
            },
            {
              path: ['$.license.number'],
              filter: {
                type: 'number',
              },
            },
            {
              path: ['$.user.name'],
              filter: {
                type: 'string',
              },
            },
          ],
        },
      },
    ],
  };
}

function getPresentationDefinitionV2_with_enum(): PresentationDefinitionV2 {
  return {
    id: '32f54163-7166-48f1-93d8-ff217bdb0653',
    name: 'Conference Entry Requirements',
    purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
    format: {
      'vc+sd-jwt': {},
    },
    input_descriptors: [
      {
        id: 'wa_driver_license',
        name: 'Washington State Business License',
        purpose: 'We can only allow licensed Washington State business representatives into the WA Business Conference',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            {
              path: ['$.vct'],
              filter: {
                type: 'string',
                enum: ['https://example.bmi.bund.de/credential/pid/1.0', 'urn:eu.europa.ec.eudi:pid:1'],
              },
            },
          ],
        },
      },
    ],
  };
}

function getPresentationDefinitionV2_const_new_pid(): PresentationDefinitionV2 {
  return {
    id: '32f54163-7166-48f1-93d8-ff217bdb0653',
    name: 'Conference Entry Requirements',
    purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
    format: {
      'vc+sd-jwt': {},
    },
    input_descriptors: [
      {
        id: 'wa_driver_license',
        name: 'Washington State Business License',
        purpose: 'We can only allow licensed Washington State business representatives into the WA Business Conference',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            {
              path: ['$.vct'],
              filter: {
                type: 'string',
                const: 'https://example.bmi.bund.de/credential/pid/1.0',
              },
            },
          ],
        },
      },
    ],
  };
}

function getPresentationDefinitionV2_const_old_pid(): PresentationDefinitionV2 {
  return {
    id: '32f54163-7166-48f1-93d8-ff217bdb0653',
    name: 'Conference Entry Requirements',
    purpose: 'We can only allow people associated with Washington State business representatives into conference areas',
    format: {
      'vc+sd-jwt': {},
    },
    input_descriptors: [
      {
        id: 'wa_driver_license',
        name: 'Washington State Business License',
        purpose: 'We can only allow licensed Washington State business representatives into the WA Business Conference',
        constraints: {
          limit_disclosure: 'required',
          fields: [
            {
              path: ['$.vct'],
              filter: {
                type: 'string',
                const: 'urn:eu.europa.ec.eudi:pid:1',
              },
            },
          ],
        },
      },
    ],
  };
}

// TODO:
//  - evaluateSubmission / submissionFrom
//  - correctly set up KB-JWT payload and sign this in the presentation callback

describe('evaluate', () => {
  it('throws error when no hasher is provided an compact sd-jwt is passed', () => {
    const pex = new PEX();
    expect(() => pex.selectFrom(getPresentationDefinitionV2(), [decodedSdJwtVc.compactSdJwtVc])).toThrow(
      'Hasher implementation is required to decode SD-JWT',
    );
  });
  it('Evaluate presentationDefinition with vc+sd-jwt format', () => {
    const pd: PresentationDefinitionV2 = getPresentationDefinitionV2();
    const result: Validated = PEX.validateDefinition(pd);
    expect(result).toEqual([{ message: 'ok', status: 'info', tag: 'root' }]);
  });

  it('selectFrom with vc+sd-jwt format compact', () => {
    const result = pex.selectFrom(getPresentationDefinitionV2(), [decodedSdJwtVc.compactSdJwtVc]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'Washington State Business License',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'wa_driver_license',
      },
    ]);
    expect(result.areRequiredCredentialsPresent).toBe('info');

    // Should have already applied selective disclosure on the SD-JWT
    expect(result.verifiableCredential).toEqual([decodedSdJwtVcWithDisclosuresRemoved.compactSdJwtVc]);
  });

  it('selectFrom with vc+sd-jwt format already decoded', () => {
    const result = pex.selectFrom(getPresentationDefinitionV2(), [decodedSdJwtVc]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'Washington State Business License',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'wa_driver_license',
      },
    ]);
    expect(result.areRequiredCredentialsPresent).toBe('info');

    // Should have already applied selective disclosure on the SD-JWT
    expect(result.verifiableCredential).toEqual([decodedSdJwtVcWithDisclosuresRemoved]);
  });

  it('presentationFrom vc+sd-jwt format', () => {
    const presentationDefinition = getPresentationDefinitionV2();
    const selectResults = pex.selectFrom(presentationDefinition, [decodedSdJwtVc]);
    const presentationResult = pex.presentationFrom(presentationDefinition, selectResults.verifiableCredential!);

    expect(presentationResult.presentationSubmission).toEqual({
      definition_id: '32f54163-7166-48f1-93d8-ff217bdb0653',
      descriptor_map: [
        {
          format: 'vc+sd-jwt',
          id: 'wa_driver_license',
          path: '$',
        },
      ],
      id: expect.any(String),
    });

    // Must be external for SD-JWT
    expect(presentationResult.presentationSubmissionLocation).toEqual(PresentationSubmissionLocation.EXTERNAL);
    expect(presentationResult.presentations[0]).toEqual({
      ...decodedSdJwtVcWithDisclosuresRemoved,
      kbJwt: {
        header: {
          typ: 'kb+jwt',
        },
        payload: {
          iat: expect.any(Number),
          nonce: undefined,
          sd_hash: calculateSdHash(decodedSdJwtVcWithDisclosuresRemoved.compactSdJwtVc, 'sha-256', hasher),
        },
      },
    });
  });

  it('verifiablePresentationFrom and evaluatePresentation with vc+sd-jwt format', async () => {
    const presentationDefinition = getPresentationDefinitionV2();
    const selectResults = pex.selectFrom(presentationDefinition, [decodedSdJwtVc]);
    let kbJwt: string | undefined = undefined;
    selectResults.verifiableCredential;
    const presentationResult = await pex.verifiablePresentationFrom(
      presentationDefinition,
      selectResults.verifiableCredential!,
      async (options) => {
        const sdJwtCredential = options.presentation as SdJwtDecodedVerifiableCredential;

        kbJwt = `${Buffer.from(
          JSON.stringify({
            ...sdJwtCredential.kbJwt?.header,
            alg: 'EdDSA',
          }),
        ).toString('base64url')}.${Buffer.from(
          JSON.stringify({
            ...sdJwtCredential.kbJwt?.payload,
            nonce: 'nonce-from-request',
            // verifier identifier url (not clear yet in HAIP what this should be, but it MUST be present)
            aud: 'did:web:something',
          }),
        ).toString('base64url')}.signature`;
        return `${sdJwtCredential.compactSdJwtVc}${kbJwt}`;
      },
      {
        presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
      },
    );

    // path_nested should not be used for sd-jwt
    expect(presentationResult.presentationSubmission.descriptor_map[0].path_nested).toBeUndefined();
    expect(presentationResult.presentationSubmission).toEqual({
      definition_id: '32f54163-7166-48f1-93d8-ff217bdb0653',
      descriptor_map: [
        {
          format: 'vc+sd-jwt',
          id: 'wa_driver_license',
          path: '$',
        },
      ],
      id: expect.any(String),
    });

    // Must be external for SD-JWT
    expect(presentationResult.presentationSubmissionLocation).toEqual(PresentationSubmissionLocation.EXTERNAL);
    // Expect the KB-JWT to be appended
    expect(presentationResult.verifiablePresentations[0]).toEqual(decodedSdJwtVcWithDisclosuresRemoved.compactSdJwtVc + kbJwt);

    const evaluateResults = pex.evaluatePresentation(presentationDefinition, presentationResult.verifiablePresentations[0], {
      presentationSubmission: presentationResult.presentationSubmission,
    });

    expect(evaluateResults).toEqual({
      // Do we want to return the compact variant here? Or the decoded/pretty variant?
      presentations: [decodedSdJwtVcWithDisclosuresRemoved.compactSdJwtVc + kbJwt],
      areRequiredCredentialsPresent: Status.INFO,
      warnings: [],
      errors: [],
      value: presentationResult.presentationSubmission,
    });
  });

  it('selectFrom with vc+sd-jwt format compact - enum new PID format', async () => {
    const result = pex.selectFrom(getPresentationDefinitionV2_with_enum(), [decodedSdJwtVcNewPid.compactSdJwtVc]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'Washington State Business License',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'wa_driver_license',
      },
    ]);
    expect(result.areRequiredCredentialsPresent).toBe('info');
  });

  it('selectFrom with vc+sd-jwt format compact - enum old PID format', async () => {
    const result = pex.selectFrom(getPresentationDefinitionV2_with_enum(), [decodedSdJwtVcOldPid.compactSdJwtVc]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'Washington State Business License',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'wa_driver_license',
      },
    ]);
    expect(result.areRequiredCredentialsPresent).toBe('info');
  });

  it('selectFrom with vc+sd-jwt format compact - const new PID format', async () => {
    const result = pex.selectFrom(getPresentationDefinitionV2_const_new_pid(), [decodedSdJwtVcNewPid.compactSdJwtVc]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'Washington State Business License',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'wa_driver_license',
      },
    ]);
    expect(result.areRequiredCredentialsPresent).toBe('info');
  });

  it('selectFrom with vc+sd-jwt format compact - const old PID format', async () => {
    const result = pex.selectFrom(getPresentationDefinitionV2_const_old_pid(), [decodedSdJwtVcOldPid.compactSdJwtVc]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'Washington State Business License',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'wa_driver_license',
      },
    ]);
    expect(result.areRequiredCredentialsPresent).toBe('info');
  });
});
