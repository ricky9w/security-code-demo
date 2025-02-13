import type { APIRoute, APIContext } from "astro";
import { hexToBytes, bytesToHex, xorBytes, blake2bHex } from "@/utils/crypto";


interface validateRequestBody {
  securityCode: string;
}

export const POST: APIRoute = async (context: APIContext) => {
  try {
    const STATIC_SALT_HEX = context.locals.runtime.env.STATIC_SALT;
    const HMAC_KEY_HEX = context.locals.runtime.env.HMAC_KEY;

    if (!STATIC_SALT_HEX || !HMAC_KEY_HEX) {
      console.error('STATIC_SALT or HMAC_KEY not provided.');
      return new Response(JSON.stringify({ error: 'Internal Error'}), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    const HMAC_KEY_BYTES = hexToBytes(HMAC_KEY_HEX);

    const requestBody = await context.request.json() as validateRequestBody;
    const userInputCode = requestBody.securityCode;

    if (!userInputCode) {
      console.warn('Missing securityCode in request body.');
      return new Response(JSON.stringify({ error: 'Invalid Request' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const [encryptedInfoHex, nonceHex, macHex] = userInputCode.split('-');
    if ([encryptedInfoHex, nonceHex, macHex].some(part => part === undefined)) {
      console.warn('Invalid security code format')
      return new Response(
        JSON.stringify({ isValid: false, error: 'Invalid security code' }),
        { status: 400, headers: { 'Content-Type':'application/json' }}
      );
    }

    let encryptedInfoBytes: Uint8Array, nonceBytes: Uint8Array;
    try {
      encryptedInfoBytes = hexToBytes(encryptedInfoHex);
      nonceBytes = hexToBytes(nonceHex);
    } catch (error: any) {
      console.warn('Invalid HEX string in security code: ', error);
      return new Response(
        JSON.stringify({ isValid: false, error: 'Invalid security code' }),
        { status: 400, headers: { 'Content-Type': 'application/json' }}
      );
    }

    const dynamicKeyHex = bytesToHex(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', hexToBytes(nonceHex + STATIC_SALT_HEX))
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
      return new Response(
        JSON.stringify({ isValid: true, sku: sku, channel: channel }),
        { status: 200, headers: { 'Content-Type': 'application/json' }}
      );
    } else {
      console.warn(`Wrong MAC in security code.\nExpected: ${expectedMacHex}\nReceived: ${macHex}`);
      return new Response(
        JSON.stringify({ isValid: false, error: 'Invalid security code'}),
        { status: 200, headers: { 'Content-Type': 'application/json' }}
      );
    }
  } catch (error: any) {
    console.error('Error validating security code: ', error);
    return new Response(
      JSON.stringify({ isValid: false, error: 'Invalid security code' }),
      { status: 500, headers: { 'Content-Type': 'application/json' }}
    );
  }
}