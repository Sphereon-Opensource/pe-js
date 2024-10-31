import { createHash } from 'crypto';

import { PresentationDefinitionV2 } from '@sphereon/pex-models';

import { PEX, Status, Validated } from '../lib';
import { SubmissionRequirementMatchType } from '../lib/evaluation/core';

export const hasher = (data: string) => createHash('sha256').update(data).digest();

const mdocBase64UrlUniversityCustomNamespace =
  'uQACam5hbWVTcGFjZXOhanVuaXZlcnNpdHmE2BhYZqRoZGlnZXN0SUQAcWVsZW1lbnRJZGVudGlmaWVyaGxvY2F0aW9ubGVsZW1lbnRWYWx1ZWlpbm5zYnJ1Y2tmcmFuZG9tWCAw6CXtd4ubXAr6uLB1GnfRyHVqhjH1_73iDASmcZefQtgYWGOkaGRpZ2VzdElEAXFlbGVtZW50SWRlbnRpZmllcmZkZWdyZWVsZWxlbWVudFZhbHVlaGJhY2hlbG9yZnJhbmRvbVgglzuY8jgQd7y_wuH47AYfzlEfzz827RRjo4k845nK5DLYGFhhpGhkaWdlc3RJRAJxZWxlbWVudElkZW50aWZpZXJkbmFtZWxlbGVtZW50VmFsdWVoSm9obiBEb2VmcmFuZG9tWCDtU0gwjxNPz1q2AjgYWkAGWSHDq7BsXzns_aMMNeVkE9gYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmNub3RsZWxlbWVudFZhbHVlaWRpc2Nsb3NlZGZyYW5kb21YICSQ7u_6OBRr8V3c5hmIeL-NKBPEaUGWPxkv8TwTPdTbamlzc3VlckF1dGiEQ6EBJqIEWDF6RG5hZWRydmd5bXpvZnhvYTRWb1VDOFJRemdwMVJnZnBCTkw1SFZuV1NKb1oyeXJhGCGBWPwwgfkwgaCgAwIBAgIQTWQTeD9zo_1knyJtFXU2hzAKBggqhkjOPQQDAjANMQswCQYDVQQGEwJERTAeFw0yNDEwMzAxNDA5MDRaFw0yNTEwMzAxNDA5MDRaMA0xCzAJBgNVBAYTAkRFMDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACx4zJR4xIci9iFJPsMUX-mu4Khh63a_hjQKef7NyM2cOjAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCRXFKtPshVsgBYMjH1-VA2sU2bphzWRLYrYvALfGTBdQIgLHF1n5J7KAiDhPTjmx3xxBlCVMYan_SKqXKxZVuO1M1ZAdDYGFkBy7kABmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhanVuaXZlcnNpdHmkAFggkN_ol8cnR2iCh3YLAYSt_-gt_hUT9ZIlm1LCS2kHW3gBWCAz2zbutIrJdbeAGi1T64jyst4PtE9WwjJK2-py9dyafQJYIHoRBZqOeV9IhNcbYsK46RaA95WyT7mq6-yqoh6j6Ds-A1ggwzOqmOGhsmiCMaEugAowlgUkzNxl0tD4CgbIx5u1Xx9tZGV2aWNlS2V5SW5mb7kAAWlkZXZpY2VLZXmkAQIgASFYIHhQ3snZrFRdtxGAB4HPsgmtZXHpzztrXjQXPRurqHtwIlggG9V2VQ1XAa9BRwxpgguzfhtP0gz8M52TWYDLwbe0P4ZnZG9jVHlwZXFvcmcuZXUudW5pdmVyc2l0eWx2YWxpZGl0eUluZm-5AARmc2lnbmVkwHQyMDI0LTEwLTMwVDE0OjA5OjA0Wml2YWxpZEZyb23AdDIwMjQtMTAtMzBUMTQ6MDk6MDRaanZhbGlkVW50aWzAdDIwMjUtMTAtMzBUMTQ6MDk6MDRabmV4cGVjdGVkVXBkYXRl91hAjkeOGOUm0CToTYOf0x3mtHFIzwT_LTHUYvcWaWrksmBOuUgZekkHAo9Bl9UTI0NKhEBIbKv9mGWHwJUgQ_1AIw';

const mdocBase64UrlUniversity =
  'uQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xhNgYWGikaGRpZ2VzdElEAHFlbGVtZW50SWRlbnRpZmllcmp1bml2ZXJzaXR5bGVsZW1lbnRWYWx1ZWlpbm5zYnJ1Y2tmcmFuZG9tWCDPDfrRde4BPN5uQhSGnm8zmhFiMm2pjTzx5z3JmEKLKdgYWGOkaGRpZ2VzdElEAXFlbGVtZW50SWRlbnRpZmllcmZkZWdyZWVsZWxlbWVudFZhbHVlaGJhY2hlbG9yZnJhbmRvbVggOUutjAeZTM2jcre7I4Gfeqy81azrsSXtbpWH65QmJTbYGFhhpGhkaWdlc3RJRAJxZWxlbWVudElkZW50aWZpZXJkbmFtZWxlbGVtZW50VmFsdWVoSm9obiBEb2VmcmFuZG9tWCD3XuNqynfdWeNM9qanYauAk5iin3lXV4eCd4RqNaCVBdgYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmNub3RsZWxlbWVudFZhbHVlaWRpc2Nsb3NlZGZyYW5kb21YICmBo2MFCt3SoUx36ZNOSPXRcA5hb1ABmy5Q5F9V6_ulamlzc3VlckF1dGiEQ6EBJqIEWDF6RG5hZXJDa3ppOERHNTZRVWN0aTJaSk1jd2ZFcFpLb2VYNW4xRlp3THZjQWZ2VHZpGCGBWPwwgfkwgaCgAwIBAgIQElXcBkTBG_kaIWLYwVbnAzAKBggqhkjOPQQDAjANMQswCQYDVQQGEwJERTAeFw0yNDEwMzAxMTAwMThaFw0yNTEwMzAxMTAwMThaMA0xCzAJBgNVBAYTAkRFMDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfu2vJOiV-lZLsM5p3CGYjMXX_hjj9LsQybiK0c9ixVujAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDVhXXnyqyJ7Y8VECpvP4sZ1jTbnQ684CmFAUR2kHuArAIgAhDDybZ9k_sAFpArd9YAlfSBgA6r2SgmhXyxfYdQ26pZAd3YGFkB2LkABmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xpABYIHxEA-V6vOFCQAuHYIYARAxRgZ_5DgIUy-i9SL_1AMRiAVggcm01ODxrEhO8x6ZsfdhiiZd-e8Qvww0z-C_jlm-rCoICWCAuLB7-RZv_qA5elyMAWDQZUTQXpR20Y-HyHOel7EsCxgNYIJE9tUTIRvZt8NJSmI4-j0NzqKUtt2DBYQZ9CpoC8o64bWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCB1WBBG2WGAzEWzM4UUUpcGFiJxtCI6sRp_o0SaMJhnNSJYIDDCu4r2F0N8khrP-Hww23HaQTW4X_-bXYwMED_orB7UZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNC0xMC0zMFQxMTowMDoyMFppdmFsaWRGcm9twHQyMDI0LTEwLTMwVDExOjAwOjIwWmp2YWxpZFVudGlswHQyMDI1LTEwLTMwVDExOjAwOjIwWm5leHBlY3RlZFVwZGF0ZfdYQNiBC_noBzIuL0HdBNCe5GWNKQ07GbRc1Kn0yQ2NE4qY6PbPzd3O4UAaTpeqHclMbHOoAJssSAbxIEooKan-vXI';
const mdocBase64UrlUniversityPresentation =
  'uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xgtgYWGGkaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YICTUPEzNlBwbcWWOXijZrs4Ed37zoxDCKJYvv0qKtpuv2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCC6uRVoNoBBcj5b-IEDTCUFoNEGVGsMSZP-3YuMUVCKrGppc3N1ZXJBdXRohEOhASaiBFgxekRuYWV0bk5naHRrNHk1VzFDNGpBM3E4VmRYbzhlUzNpWWViRm5MR3I3ZlhTYVVUNhghgVj8MIH5MIGgoAMCAQICEF36OiPSysIvMaLWuTCava8wCgYIKoZIzj0EAwIwDTELMAkGA1UEBhMCREUwHhcNMjQxMDMwMTI1ODQ0WhcNMjUxMDMwMTI1ODQ0WjANMQswCQYDVQQGEwJERTA5MBMGByqGSM49AgEGCCqGSM49AwEHAyIAA6VBlDzOG438-hsPWMSY56vJWrz8m5OaIimg0rG0vY6towIwADAKBggqhkjOPQQDAgNIADBFAiBc_30LjkQFX9YxWUyYH5jFK4Smw2h4KKYU85BBH2xDTAIhAKqb7RwT5_qoVJNYcom0x3N1eVd49TuPZfkbNaZsmhi5WQHd2BhZAdi5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaQAWCDrF96Sw8aHk1fZ8B92ZQE7I37MHjVSDoEq4MGhHuMIcwFYIAEsfqF7G_6k-lw2NKPRwHlWSalgrYsbXdcqz1ghPa-nAlggGq9DTWd1xmO8O84B0PCKhtf0daiT34V4xkU-wSGHYUwDWCDX5TNczi_TZSwmJ1VVeEzXpKXR9eweibocvAfpmKHEU21kZXZpY2VLZXlJbmZvuQABaWRldmljZUtleaQBAiABIVggN4_nyaOESmuHV8xhsUl2VqxaF83kIraAc2GV7M2-BKEiWCC0GqqvYnJ6U12ccZVDAOH8CeNGs9oOAF46jXJfauTSO2dkb2NUeXBlcW9yZy5ldS51bml2ZXJzaXR5bHZhbGlkaXR5SW5mb7kABGZzaWduZWTAdDIwMjQtMTAtMzBUMTI6NTg6NDRaaXZhbGlkRnJvbcB0MjAyNC0xMC0zMFQxMjo1ODo0NFpqdmFsaWRVbnRpbMB0MjAyNS0xMC0zMFQxMjo1ODo0NFpuZXhwZWN0ZWRVcGRhdGX3WEC3VoysIcxum_HtX5OCFEA3BwzhHcYmESJDzY58vz0Ez7Zo3fmP3D0M8evzMk7_Cz7_hwVL8sdLgiKpho5UXrunbGRldmljZVNpZ25lZLkAAmpuYW1lU3BhY2Vz2BhDuQAAamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag91hA9peGbzwyivN7UXvk4smItYMdt-RvcU87ZvXdDfRqIQsWSxGLcke2lHcit77fIEAw_8w0MOzM7ObQWK3T4vTMl2lkZXZpY2VNYWP3ZnN0YXR1cwA';

const mdocBase64UrlPid =
  'omppc3N1ZXJBdXRohEOhASahGCGCWQJ4MIICdDCCAhugAwIBAgIBAjAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDgxMzE3WhcNMjUwNzA1MDgxMzE3WjBsMQswCQYDVQQGEwJERTEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxCjAIBgNVBAsMAUkxMjAwBgNVBAMMKVNQUklORCBGdW5rZSBFVURJIFdhbGxldCBQcm90b3R5cGUgSXNzdWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf_7E7VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduKOBkDCBjTAdBgNVHQ4EFgQUiPhCkLErDXPLW2_J0WVeghyw-mIwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwLQYDVR0RBCYwJIIiZGVtby5waWQtaXNzdWVyLmJ1bmRlc2RydWNrZXJlaS5kZTAfBgNVHSMEGDAWgBTUVhjAiTjoDliEGMl2Yr-ru8WQvjAKBggqhkjOPQQDAgNHADBEAiAbf5TzkcQzhfWoIoyi1VN7d8I9BsFKm1MWluRph2byGQIgKYkdrNf2xXPjVSbjW_U_5S5vAEC5XxcOanusOBroBbVZAn0wggJ5MIICIKADAgECAhQHkT1BVm2ZRhwO0KMoH8fdVC_vaDAKBggqhkjOPQQDAjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwHhcNMjQwNTMxMDY0ODA5WhcNMzQwNTI5MDY0ODA5WjCBiDELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMTYwNAYDVQQDDC1TUFJJTkQgRnVua2UgRVVESSBXYWxsZXQgUHJvdG90eXBlIElzc3VpbmcgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgbN3AUOdzv4qfmJsC8I4zyR7vtVDGp8xzBkvwhogD5YJE5wJ-Zj-CIf3aoyu7mn-TI6K8TREL8ht0w428OhTJo2YwZDAdBgNVHQ4EFgQU1FYYwIk46A5YhBjJdmK_q7vFkL4wHwYDVR0jBBgwFoAU1FYYwIk46A5YhBjJdmK_q7vFkL4wEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDRwAwRAIgYSbvCRkoe39q1vgx0WddbrKufAxRPa7XfqB22XXRjqECIG5MWq9Vi2HWtvHMI_TFZkeZAr2RXLGfwY99fbsQjPOzWQRA2BhZBDumZ2RvY1R5cGV3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjFndmVyc2lvbmMxLjBsdmFsaWRpdHlJbmZvo2ZzaWduZWR0MjAyNC0wNi0yNFQwNjo1MDo0MFppdmFsaWRGcm9tdDIwMjQtMDYtMjRUMDY6NTA6NDBaanZhbGlkVW50aWx0MjAyNC0wNy0wOFQwNjo1MDo0MFpsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMbYAWCDJVfFwuYp2QoZROAvEN2pyUZ1KM8pEWRZXfdWrF1HkigFYIHhpl7kR5NAjeLSFJd0LsjMB9_ZeOBi-pYiOSwG78rrEAlggEih2FMRoq01sCrA8gZ-r_pUqi7add99aSg_l9iuV7w8DWCD9umaT-ULFoZSewraVNXFFWf3iNm5rgj75OQAy7n-1HQRYIL8xH7_OLXmsTruVMI1AInTjtDyPiDkk3ZaljsXFMaeYBVgg2-7WIwtpcZgVI3ZpKiFOqf8cV_R8G20adAqk3xLmaR8GWCCMFjcNb1Yp0rw86h1OOYCPzIhE-Dt5yWCQ7BTpNbZBuwdYIEzmGyjypgomuuwlwyp44zLi6sXT11ZNoyDAMKEsNP0pCFggI2ENhbCnOrZsVvqNE1GJe13ygY7MMU_Hv7l7j60Y5BgJWCBDZb6ztiG-09jmZNNc3Qi4e1OhyqtNmrOxzuzCtMYKcgpYIDGYllJw4PxQlyaeiI-a0qaeD9C3qh2hKXtvYYol928zC1gg4etokah75K55-qzJ6_FtE2KtAF9gy3gzcTeirdZ3LHwMWCDnCnqeX1M1iJe3LH2qc0kJOXQHYUEubpqVi2c4wtt3xQ1YIL7dVtgkdG9n2pDvrBtgY21i7X7YyiVCe-p61mtghwjnDlggQk4FkmKScm6oCwHtt5Og5E_1SQfuWpFIMdj0x8ZCS0wPWCBGMDXYqqBPDqeqBoFn3IKJSZWcdMj7KyU1ZtNOZ3OE6hBYIJyzjluOe_VlYSQw1aIBcrsnnF2czy5ypChycRfi0nrOEVggKOd_n9xKuZDdnak-vQ1zrIzSWLxJIlPgJMpLEn2FuLYSWCBHx1eoCb1ydVj_EGIKUOYPCyEjAgP5HxN-J_zSZUwkKBNYIN0hCZPdhjF4pU-LVEoQi7FdOSF3lrQ8EimA7C31NcVhFFggxtk6j0328cyjnwNoWKCUgvg1Uk37Bktpzb4atlRT5VIVWCAMujq43dRJg7XilJJL0z-hxQoLUpkzO2tq6H6LazG0uW1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIMrI7GWNvKwCXqwcJmkBMyIRAXejiET9PRAFCMhJEfo9IlggEvXLy65sT8QyzLnWsC7aIM1eem2029awDcWI7WO0ES9vZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZYQLVKBk4WMWUjTFWSwUuz7vCPNCAqw5x7HIBHVr1H_gC5WOEXxBaFlnxHYBjBguFSfLe5e-7t82ySdef7uvo6d2NqbmFtZVNwYWNlc6F3ZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjGW2BhYVqRmcmFuZG9tUPYpQ7wOENpcyi6n1L56UdhoZGlnZXN0SUQAbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcnByZXNpZGVudF9jb3VudHJ52BhYT6RmcmFuZG9tUMRgxk_vnHlF0GwDT1_ULxJoZGlnZXN0SUQBbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTLYGFhbpGZyYW5kb21QKjeWt5G4r5-qtZytkvPCY2hkaWdlc3RJRAJsZWxlbWVudFZhbHVlZkdBQkxFUnFlbGVtZW50SWRlbnRpZmllcnFmYW1pbHlfbmFtZV9iaXJ0aNgYWFOkZnJhbmRvbVBDbqFvUf9mgbrDQOa3wxwcaGRpZ2VzdElEA2xlbGVtZW50VmFsdWVlRVJJS0FxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZdgYWFSkZnJhbmRvbVC0poiPe3Qx58JWmtP7Q_WGaGRpZ2VzdElEBGxlbGVtZW50VmFsdWUZB6xxZWxlbWVudElkZW50aWZpZXJuYWdlX2JpcnRoX3llYXLYGFhPpGZyYW5kb21Qu7cn53_6IG1TiAz9anV2VGhkaWdlc3RJRAVsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xONgYWE-kZnJhbmRvbVCRPYwpMh16--3IgrBqvPiHaGRpZ2VzdElEBmxlbGVtZW50VmFsdWX1cWVsZW1lbnRJZGVudGlmaWVya2FnZV9vdmVyXzIx2BhYVqRmcmFuZG9tUGu5N18O3ztKBJRIqXuXprFoZGlnZXN0SUQHbGVsZW1lbnRWYWx1ZWVLw5ZMTnFlbGVtZW50SWRlbnRpZmllcm1yZXNpZGVudF9jaXR52BhYbKRmcmFuZG9tUDKXb5L9OGRMoOqY4ixLrj5oZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZaJldmFsdWViREVrY291bnRyeU5hbWVnR2VybWFueXFlbGVtZW50SWRlbnRpZmllcmtuYXRpb25hbGl0edgYWFmkZnJhbmRvbVD4nB3KeJEBfi7oTQaUgKmcaGRpZ2VzdElECWxlbGVtZW50VmFsdWVqTVVTVEVSTUFOTnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWFWkZnJhbmRvbVDzJdpDC6MZvIaVDJ_psS7JaGRpZ2VzdElECmxlbGVtZW50VmFsdWVmQkVSTElOcWVsZW1lbnRJZGVudGlmaWVya2JpcnRoX3BsYWNl2BhYVaRmcmFuZG9tUKEIada4bfyv5GeAbFb3reZoZGlnZXN0SUQLbGVsZW1lbnRWYWx1ZWJERXFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnnYGFhPpGZyYW5kb21Qqbo3TPNv6ilm7tvlR4l_GGhkaWdlc3RJRAxsZWxlbWVudFZhbHVl9HFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl82NdgYWGykZnJhbmRvbVC_nvMTClyTddZfwm_WviXAaGRpZ2VzdElEDWxlbGVtZW50VmFsdWWiZG5hbm8aNQgmzGtlcG9jaFNlY29uZBpmeRdAcWVsZW1lbnRJZGVudGlmaWVybWlzc3VhbmNlX2RhdGXYGFhqpGZyYW5kb21QPqCKymVJhGPADlN7tILk2mhkaWdlc3RJRA5sZWxlbWVudFZhbHVlomRuYW5vGjUIJsxrZXBvY2hTZWNvbmQaZouMQHFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZdgYWGOkZnJhbmRvbVC0Cd-E5IjcJYTHKNzujqXlaGRpZ2VzdElED2xlbGVtZW50VmFsdWVwSEVJREVTVFJB4bqeRSAxN3FlbGVtZW50SWRlbnRpZmllcm9yZXNpZGVudF9zdHJlZXTYGFhPpGZyYW5kb21QBSfulxP_wSm8WUJ31jD9U2hkaWdlc3RJRBBsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNtgYWF2kZnJhbmRvbVDAyvF8NuW7ZU4yWPFlZEQ9aGRpZ2VzdElEEWxlbGVtZW50VmFsdWVlNTExNDdxZWxlbWVudElkZW50aWZpZXJ0cmVzaWRlbnRfcG9zdGFsX2NvZGXYGFhYpGZyYW5kb21QH_0ki1hqwWblAMFbrwMO2GhkaWdlc3RJRBJsZWxlbWVudFZhbHVlajE5NjQtMDgtMTJxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWFekZnJhbmRvbVBaUAbNICOqTrrbEaDKqbtSaGRpZ2VzdElEE2xlbGVtZW50VmFsdWViREVxZWxlbWVudElkZW50aWZpZXJxaXNzdWluZ19hdXRob3JpdHnYGFhPpGZyYW5kb21QtyDyyKiExuZFhmsIS1M122hkaWdlc3RJRBRsZWxlbWVudFZhbHVl9XFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xNNgYWFGkZnJhbmRvbVAIbRM0JOd2WfpsMlmrMWMaaGRpZ2VzdElEFWxlbGVtZW50VmFsdWUYO3FlbGVtZW50SWRlbnRpZmllcmxhZ2VfaW5feWVhcnM';

const sdJwt =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzMwMjkzMTIzLCJfc2QiOlsiVEtuSUJwVGp3ZmpVdFZra3ZBUWNrSDZxSEZFbmFsb1ZtZUF6UmlzZlNNNCIsInRLTFAxWFM3Vm55YkJET2ZWV3hTMVliNU5TTjhlMVBDMHFqRnBnbjd5XzgiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.GhgxbTA_cLZ6-enpOrTRqhIoZEzJoJMSQeutQdhcIayhiem9yd8i0x-h6NhQbN1NrNPwi-JQhy5lpNopVia_AA~WyI3NDU5ODc1MjgyODgyMTY5MjY3NTk1MTgiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFZERTQSJ9.eyJpYXQiOjE3MzAyOTMxMjYsIm5vbmNlIjoiOTExNTE4Nzc5ODY4MjIzNzcxOTk1NTA1IiwiYXVkIjoibG9jYWxob3N0OjEyMzQiLCJzZF9oYXNoIjoiRmFlcWFCVFZ1TXhEVUJvVHlwUnhycE9wTkRZZUtDQjV0a1VsNEpWdjJ4dyJ9.mLFA6FA04KVQljy9i8OMuOsarWNOyGZYltkVIUMMWoXXKnbKT5eoPNCigVs0g5y9ucgdQBuMLKxCgQx4SRwsBQ';

const pex = new PEX({
  hasher,
});

function getPresentationDefinitionV2(withSdJwtInputDescriptor = false): PresentationDefinitionV2 {
  const pd: PresentationDefinitionV2 = {
    id: 'mDL-sample-req',
    input_descriptors: [
      {
        id: 'org.eu.university',
        format: {
          mso_mdoc: {
            alg: ['ES256', 'ES384', 'ES512', 'EdDSA', 'ESB256', 'ESB320', 'ESB384', 'ESB512'],
          },
        },
        constraints: {
          fields: [
            {
              path: ["$['eu.europa.ec.eudi.pid.1']['name']"],
              intent_to_retain: false,
            },
            {
              path: ["$['eu.europa.ec.eudi.pid.1']['degree']"],
              intent_to_retain: false,
            },
          ],
          limit_disclosure: 'required',
        },
      },
    ],
  };

  if (withSdJwtInputDescriptor) {
    pd.input_descriptors.push({
      id: 'OpenBadgeCredentialDescriptor',
      format: {
        'vc+sd-jwt': {
          'sd-jwt_alg_values': ['EdDSA'],
        },
      },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ['$.vct'],
            filter: {
              type: 'string',
              const: 'OpenBadgeCredential',
            },
          },
          {
            path: ['$.university'],
          },
        ],
      },
    });
  }

  return pd;
}

describe('evaluate mdoc', () => {
  it('Evaluate presentationDefinition with mso_mdoc format', () => {
    const pd = getPresentationDefinitionV2();
    const result: Validated = PEX.validateDefinition(pd);
    expect(result).toEqual([{ message: 'ok', status: 'info', tag: 'root' }]);
  });

  it('selectFrom with mso_mdoc format encoded', () => {
    const result = pex.selectFrom(getPresentationDefinitionV2(), [mdocBase64UrlPid, mdocBase64UrlUniversity, mdocBase64UrlUniversityCustomNamespace]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'org.eu.university',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'org.eu.university',
      },
    ]);
    expect(result.verifiableCredential).toEqual([mdocBase64UrlUniversity]);
    expect(result.areRequiredCredentialsPresent).toBe('info');
  });

  it('selectFrom with both mso_mdoc and vc+sd-jwt format encoded', () => {
    const result = pex.selectFrom(getPresentationDefinitionV2(true), [
      sdJwt,
      mdocBase64UrlPid,
      mdocBase64UrlUniversity,
      mdocBase64UrlUniversityCustomNamespace,
    ]);
    expect(result.errors?.length).toEqual(0);
    expect(result.matches).toEqual([
      {
        name: 'org.eu.university',
        rule: 'all',
        vc_path: ['$.verifiableCredential[0]'],
        type: SubmissionRequirementMatchType.InputDescriptor,
        id: 'org.eu.university',
      },
      {
        id: 'OpenBadgeCredentialDescriptor',
        name: 'OpenBadgeCredentialDescriptor',
        rule: 'all',
        type: SubmissionRequirementMatchType.InputDescriptor,
        vc_path: ['$.verifiableCredential[1]'],
      },
    ]);
    expect(result.verifiableCredential).toEqual([mdocBase64UrlUniversity, sdJwt]);
    expect(result.areRequiredCredentialsPresent).toBe('info');
  });

  it('evaluatePresentation with mso_mdoc format', async () => {
    const presentationDefinition = getPresentationDefinitionV2();
    const submission = {
      definition_id: presentationDefinition.id,
      descriptor_map: [
        {
          format: 'mso_mdoc',
          id: 'org.eu.university',
          path: '$[0]',
        },
      ],
      id: '2d0b0be7-9d91-4760-ad58-f204f9f39de7',
    };
    const evaluateResults = pex.evaluatePresentation(presentationDefinition, [mdocBase64UrlUniversityPresentation], {
      presentationSubmission: submission,
    });

    expect(evaluateResults).toEqual({
      presentations: [mdocBase64UrlUniversityPresentation],
      areRequiredCredentialsPresent: Status.INFO,
      warnings: [],
      errors: [],
      value: submission,
    });
  });

  it('evaluatePresentation with mso_mdoc format generating a submission', async () => {
    const presentationDefinition = getPresentationDefinitionV2();
    const evaluateResults = pex.evaluatePresentation(presentationDefinition, [mdocBase64UrlUniversityPresentation], {
      generatePresentationSubmission: true,
    });

    expect(evaluateResults).toEqual({
      presentations: [mdocBase64UrlUniversityPresentation],
      areRequiredCredentialsPresent: Status.INFO,
      warnings: [],
      errors: [],
      value: {
        definition_id: presentationDefinition.id,
        descriptor_map: [
          {
            format: 'mso_mdoc',
            id: 'org.eu.university',
            path: '$[0]',
          },
        ],
        id: expect.any(String),
      },
    });
  });

  it('evaluatePresentation with both mso_mdoc and vc+sd-jwt format', async () => {
    const presentationDefinition = getPresentationDefinitionV2(true);
    const submission = {
      definition_id: presentationDefinition.id,
      descriptor_map: [
        {
          format: 'mso_mdoc',
          id: 'org.eu.university',
          path: '$[0]',
        },
        {
          format: 'vc+sd-jwt',
          id: 'OpenBadgeCredentialDescriptor',
          path: '$[1]',
        },
      ],
      id: '2d0b0be7-9d91-4760-ad58-f204f9f39de7',
    };
    const evaluateResults = pex.evaluatePresentation(presentationDefinition, [mdocBase64UrlUniversityPresentation, sdJwt], {
      presentationSubmission: submission,
    });

    expect(evaluateResults).toEqual({
      presentations: [mdocBase64UrlUniversityPresentation, sdJwt],
      areRequiredCredentialsPresent: Status.INFO,
      warnings: [],
      errors: [],
      value: submission,
    });
  });
});
