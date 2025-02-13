import type { APIRoute, APIContext } from "astro";
import { hexToBytes, bytesToHex, xorBytes, blake2bHex } from "@/utils/crypto";


interface validateRequestBody {
  securityCode: string;
}

const validateSecurityCode = async (securityCode: string, staticSaltHex: string, hmacKeyHex: string) => {
  if (!staticSaltHex || !hmacKeyHex) {
    console.error('STATIC_SALT or HMAC_KEY not provided.');
    return { status: 500, body: { error: 'Internal Error' }};
  }

  const HMAC_KEY_BYTES = hexToBytes(hmacKeyHex);

  const userInputCode = securityCode;

  if (!userInputCode) {
    console.warn('Missing security code.');
    return { status: 400, body: { error: 'Invalid Request' } };
  }

  const [encryptedInfoHex, nonceHex, macHex] = userInputCode.split('-');
  if ([encryptedInfoHex, nonceHex, macHex].some(part => part === undefined)) {
    console.warn('Invalid security code format');
    return { status: 400, body: { isValid: false, error: 'Invalid security code' } };
  }

  let encryptedInfoBytes: Uint8Array, nonceBytes: Uint8Array;
  try {
    encryptedInfoBytes = hexToBytes(encryptedInfoHex);
    nonceBytes = hexToBytes(nonceHex);
  } catch (error: any) {
    console.warn('Invalid HEX string in security code: ', error);
    return { status: 400, body: { isValid: false, error: 'Invalid security code' } };
  }

  const dynamicKeyHex = bytesToHex(
    new Uint8Array(
      await crypto.subtle.digest('SHA-256', hexToBytes(nonceHex + staticSaltHex))
    ).slice(0, 4)
  );

  const dynamicKeyBytes = hexToBytes(dynamicKeyHex);
  const decryptedInfoBytes = xorBytes(encryptedInfoBytes, dynamicKeyBytes);

  const dataForMac = new Uint8Array([...encryptedInfoBytes, ...nonceBytes]);
  const expectedMacHex = blake2bHex(dataForMac, HMAC_KEY_BYTES, 8);

  if (expectedMacHex === macHex) {
    const productInfoHex = bytesToHex(decryptedInfoBytes);
    const sku = productInfoHex.substring(0, 6);
    const channel = productInfoHex.substring(6, 8);
    return { status: 200, body: { isValid: true, sku: sku, channel: channel } };
  } else {
    console.warn(`Wrong MAC in security code.\nExpected: ${expectedMacHex}\nReceived: ${macHex}`);
    return { status: 200, body: { isValid: false, error: 'Invalid security code' } }; // 状态码保持 200
  }
}

export const POST: APIRoute = async (context: APIContext) => {
  try {
    const STATIC_SALT_HEX = context.locals.runtime.env.STATIC_SALT;
    const HMAC_KEY_HEX = context.locals.runtime.env.HMAC_KEY;
    
    const requestBody = await context.request.json() as validateRequestBody;
    const securityCode = requestBody.securityCode;

    const validateResult = await validateSecurityCode(securityCode, STATIC_SALT_HEX, HMAC_KEY_HEX);
    return new Response(JSON.stringify(validateResult.body), {
      status: validateResult.status,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error: any) {
    console.error('Error validating security code: ', error);
    return new Response(
      JSON.stringify({ error: 'Invalid security code' }),
      { status: 500, headers: { 'Content-Type': 'application/json' }}
    );
  }
}

export const GET: APIRoute = async (context: APIContext) => {
  try {
    const STATIC_SALT_HEX = context.locals.runtime.env.STATIC_SALT;
    const HMAC_KEY_HEX = context.locals.runtime.env.HMAC_KEY;

    const securityCode = context.url.searchParams.get('code');
    const validateResult = await validateSecurityCode(securityCode || "", STATIC_SALT_HEX, HMAC_KEY_HEX);
    return new Response(JSON.stringify(validateResult.body), {
      status: validateResult.status,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error: any) {
    console.error('Error validating security code: ', error);
    return new Response(
      JSON.stringify({ error: 'Invalid security code' }),
      { status: 500, headers: { 'Content-Type': 'application/json' }}
    );
  }
}